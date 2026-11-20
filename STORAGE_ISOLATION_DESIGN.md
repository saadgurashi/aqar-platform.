# تصميم عزل التخزين والمستندات الخاصة — منصة عقار 2.0

**المرجع:** القسم 3.9 (Storage isolation) و15 (مزود التخزين S3-compatible) والمخطط الفني الكامل (القسم 6).

## 1. فصل التخزين العام عن الخاص
- **المستندات الخاصة (`property_documents`, `owner_authorizations`) والوسائط الخاصة (`property_media` حيث `visibility = 'private'`):** تُخزن في حاوية خاصة (Private Bucket) غير قابلة للوصول العام إطلاقاً.
- يفرض قيد `CHECK` على قاعدة البيانات منع تخزين أي رابط `http://` أو `https://` أو مسار يحتوي على `..` في أعمدة `private_storage_key` و`storage_key`.

## 2. نمط مفاتيح التخزين المعزولة وغير القابلة للتخمين
- يُولّد كل مفتاح خادمياً عبر `generateOpaqueStorageKey()` بالصيغة:
  `tenants/<organization_id>/<category>/<uuid>-<32-hex-random>.<ext>`
- لا تُستخدم أسماء الملفات المرفوعة من المستخدم أو الأرقام التسلسلية، ويُرفض أي مسار يحاول اجتياز المجلدات (`..` أو `\` أو `/`).

## 3. تدفق إصدار والتحقق من الروابط الموقّعة قصيرة الصلاحية
1. يطلب العميل رابط تنزيل عبر `POST /api/v1/storage/signed-url` (مع Cookie الجلسة + Origin + `X-CSRF-Token`).
2. يتحقق الخادم عبر `guardProtectedRequest()` من الجلسة النشطة والعضوية والصلاحية (`properties.view` أو `properties.verify`).
3. يستعلم الخادم عن السجل ضمن سياق RLS، ويتحقق من تطابق `fileRecord.organizationId === verifiedContext.organizationId`.
4. عند نجاح التحقق فقط، يصدر `PrivateStorageService` رابطاً موقّعاً بـ `HMAC-SHA256` (بمفتاح خادمي لا يظهر في كود العميل) وبمدة صلاحية قصيرة (افتراضياً **120 ثانية** وبحد أقصى **300 ثانية**).
5. عند استدعاء `GET /api/v1/storage/download`، يتحقق الخادم من التوقيع بـ `timingSafeEqual` ومن عدم انتهاء الصلاحية ومن مطابقة بادئة المؤسسة قبل تسليم الملف.
6. **قاعدة إلزامية:** الرابط الموقّع ليس بديلاً عن التحقق من الصلاحية عند طلب إنشاء الرابط، ولا يُجدَّد تلقائياً دون إعادة التحقق الخادمي.

## 4. قرار معلق قبل الإنتاج (القسم 15)
- اختيار مزود التخزين `S3-compatible` الفعلي وموقع البيانات وسياسة الاحتفاظ لم يُعتمد بعد؛ الخدمة معزولة خلف طبقة `PrivateStorageService` لتُربط بالمزود المعتمد فور قرارك.

## 5. التحقق التكاملي مع PostgreSQL وCI
- يقرأ `PgAuthRepository.findPrivateFileById()` سجل المستند أو الوسيط من `property_documents` / `property_media` داخل `withTenantTransaction()` المحكوم بـ `FORCE RLS` ودور `aqar_app`.
- يختبر `tests/integration/pg_rls.integration.test.mjs` مسار إصدار الرابط الموقّع ومنع IDOR عبر المؤسسات مباشرة أمام قاعدة PostgreSQL 16 مؤقتة في `.github/workflows/ci.yml` مع حفظ تقارير الاختبار في `ci-reports/`.
