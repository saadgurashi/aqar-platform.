# وثائق A9 — مخطط تدفق المصادقة، مصفوفة الصلاحيات، ودليل إضافة جدول محمي بـ RLS

**المرجع:** منصة عقار 2.0 (القسم 3 و16 — تعريف إنجاز Sprint 1).

---

## 1. مخطط تدفق المصادقة والتحقق من الصلاحيات

```text
[المتصفح / PWA]
   │  1) POST /api/v1/auth/otp/request (Origin + identifier + deviceId)
   ▼
[API Guard] ──► فحص Origin + Rate Limiter متعدد الأبعاد (Account + IP + Device)
   │  2) توليد OTP (randomInt) + حفظ HMAC-SHA256(salt + pepper) في otp_challenges
   │  3) إرسال عبر OtpDeliveryProvider (مفصول؛ يرفض العمل إن لم يُعتمد مزود)
   ▼
[POST /api/v1/auth/otp/verify]
   │  4) فحص الصلاحية + الاستخدام الوحيد + max_attempts + مقارنة timingSafeEqual
   │  5) استهلاك OTP فوراً (consumed_at) + فرض MFA لأدوار Owner / Manager / Platform Admin
   │  6) إصدار جلسة جديدة + كوكي HttpOnly/Secure/SameSite=Lax + كوكي CSRF
   ▼
[أي طلب API محمي: /api/v1/*]
   │  7) guardProtectedRequest():
   │     - فحص كوكي الجلسة + idle_timeout_at + expires_at + revoked_at
   │     - فحص Origin + X-CSRF-Token مقابل csrf_token_hash (لعمليات التعديل)
   │     - رفض أي organization_id أو user_id مزور من العميل
   │     - تشغيل evaluateAuthorization() (العضوية النشطة + الأدوار + permission_overrides + الملكية + SoD)
   ▼
[withTenantTransaction() -> PostgreSQL (دور aqar_app بلا BYPASSRLS)]
   │  8) BEGIN -> set_config('app.user_id', ..., true) + set_config('app.organization_id', ..., true)
   │  9) تنفيذ الاستعلام تحت ENABLE + FORCE ROW LEVEL SECURITY + قيود FK المركبة
   │ 10) تسجيل الحدث الحساس المنقّح في audit_logs (append-only) -> COMMIT
```

---

## 2. مصفوفة الأدوار والصلاحيات الأساسية (القسم 3.2 و3.3)

| الدور | النطاق | MFA إلزامي | الصلاحيات الأساسية | قيود رئيسية |
| :--- | :--- | :---: | :--- | :--- |
| `owner` | المكتب | نعم | جميع صلاحيات المكتب الـ 39 | يخضع لـ SoD في اعتماد الدفعات إن فُعلت سياسة المكتب |
| `manager` | المكتب | نعم | إدارة العقارات والعملاء والمعاينات والمهام والصفقات ودعوة الموظفين والتقارير | لا يملك تلقائياً `roles.manage` أو `organization.settings.manage` أو `finance.refunds.approve` |
| `agent` | المكتب | اختياري | `properties.view/create/update.own`، العملاء، المعاينات، المهام، الصفقات (إنشاء/تحديث) | لا يعدّل عقارات غيره، ولا ينشر أو يدير الأدوار |
| `viewer` | المكتب | اختياري | `properties.view`, `contacts.view`, `viewings.view`, `reports.view` | قراءة فقط دون أي تعديل أو تصدير |
| `accountant` | اختياري | اختياري | صلاحيات الفواتير والمدفوعات ودفتر الأستاذ وكشوف الحساب والتقارير | يخضع لفصل الواجبات (SoD): لا يعتمد دفعة أنشأها بنفسه |
| `verification_officer` | اختياري | اختياري | `properties.view`, `properties.verify` | مراجعة المستندات فقط دون أي اعتماد مالي |
| `platform_admin` | المنصة | نعم | `audit_logs.view`, `reports.view` عبر مسار منصة منفصل ومراقب | كل وصول لبيانات مكتب يجب أن يكون مسبباً وموثقاً في `audit_logs` |

---

## 3. دليل إضافة جدول جديد محمي بـ RLS (خطوة بخطوة)

عند إضافة أي جدول جديد تابع لمكتب في أي حزمة قادمة (B–G)، يُلزم تنفيذ الخطوات الـ 6 التالية بالترتيب:

1. **إنشاء Migration مرقّم جديد** تحت `db/migrations/NNNN_<name>.sql` دون تعديل أي migration سابق.
2. **تصميم الأعمدة والقيود وفق القسم 2.3 و3.7:**
   - استخدام `uuid` للمعرفات و`timestamptz` (UTC) للتواريخ و`numeric` للمبالغ (يُمنع `float`/`real`/`double precision`).
   - إضافة `organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT`.
   - إضافة `CONSTRAINT <tbl>_org_id_id_unique UNIQUE (organization_id, id)` إذا كان للجدول جداول تابعة.
   - ربط أي أب تابع للمكتب بمفتاح أجنبي مركب:
     ```sql
     CONSTRAINT <child>_<parent>_same_org_fk
       FOREIGN KEY (organization_id, <parent_id>)
       REFERENCES <parent_table>(organization_id, id) ON DELETE RESTRICT
     ```
3. **تفعيل وفرض RLS إلزامياً:**
   ```sql
   ALTER TABLE <new_table> ENABLE ROW LEVEL SECURITY;
   ALTER TABLE <new_table> FORCE ROW LEVEL SECURITY;

   CREATE POLICY <new_table>_tenant_isolation ON <new_table>
     USING (organization_id = app_current_org_id() OR app_is_platform_admin())
     WITH CHECK (organization_id = app_current_org_id() OR app_is_platform_admin());
   ```
4. **منح أقل الصلاحيات لدور `aqar_app`:**
   ```sql
   GRANT SELECT, INSERT, UPDATE, DELETE ON <new_table> TO aqar_app;
   -- ولجداول السجلات التاريخية فقط: GRANT SELECT, INSERT + REVOKE UPDATE, DELETE
   ```
5. **استخدام `withTenantTransaction` في طبقة التطبيق:**
   - لا تنفذ أي استعلام خارج `withTenantTransaction(client, guard.verifiedContext, async (tx) => ...)`.
6. **إضافة الاختبارات قبل اعتبار الجدول مكتملاً:**
   - إضافة اختبار ثابت يتحقق من `ENABLE/FORCE RLS` والقيود المركبة.
   - إضافة حالة اختبار عزل سلبية في `tests/security/rls_isolation_matrix.sql` وتمريرها على PostgreSQL حقيقي ضمن CI.

---

## 4. إعداد اتصال PostgreSQL وإدارة المعاملات والأخطاء وConnection Pool

1. **فصل أدوار الاتصال:**
   - `DATABASE_URL`: مالك الجداول (`aqar_owner`) يُستخدم **حصراً** لتطبيق ملفات `db/migrations/*.sql` في CI/النشر، ولا يُستخدم في تشغيل تطبيق الويب أو API.
   - `APP_DATABASE_URL`: دور التطبيق (`aqar_app_login` الوراث من `aqar_app`) بصلاحيات `NOBYPASSRLS NOSUPERUSER NOCREATEDB NOCREATEROLE`، ويُستخدم لجميع استعلامات التطبيق واختبارات العزل.
2. **دورة المعاملة وعزل Connection Pool (`PgAuthRepository`):**
   - كل استعلام خاص بمؤسسة يُنفّذ عبر `runInTenantTx()` → `withTenantTransaction()` التي تبدأ بـ `BEGIN`، وتضبط `set_config('app.user_id', ..., true)` و`set_config('app.organization_id', ..., true)` و`set_config('app.platform_admin', 'false', true)` محلياً للمعاملة فقط (`is_local = true`).
   - عند أي خطأ تُنفّذ `ROLLBACK` تلقائياً، وفي كتلة `finally` يُعاد الاتصال إلى الـ Pool عبر `client.release()`، وبذلك لا يتسرب سياق مؤسسة سابقة إلى أي اتصال معاد استخدامه.
3. **التحقق في CI:**
   - يثبت `tests/integration/pg_rls.integration.test.mjs` العزل باستخدام `Pool({ max: 1 })` مع تراجع متعمّد (`INTENTIONAL_ROLLBACK_TEST`) في المؤسسة أ يليه مباشرة استعلام للمؤسسة ب على نفس الاتصال الفيزيائي.
