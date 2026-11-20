# تصميم المصادقة والجلسات وحماية CSRF وRate Limiting — منصة عقار 2.0

## 1. تخزين رموز OTP وأسرار الجلسات
- لا يُخزّن أي رمز OTP أو رمز جلسة أو رمز استرداد MFA كنص صريح في قاعدة البيانات أو السجلات.
- يُشتق `code_hash` و`token_hash` و`csrf_token_hash` عبر `HMAC-SHA256` مع مفتاح خادمي (`secretPepper`) و`salt` فريد لكل تحدي OTP، وتُجرى المقارنة عبر `crypto.timingSafeEqual`.
- رموز OTP أحادية الاستخدام (`consumed_at`) وتنتهي بعد 5 دقائق وتُقفل بعد 5 محاولات خاطئة.

## 2. ملفات تعريف الارتباط الآمنة (Cookies) ومنع `localStorage`
- يُمنع إرجاع رمز الجلسة في جسم JSON أو تخزينه في `localStorage`.
- يُصدر الخادم كوكي الجلسة `__Host-aqar_session` بالخصائص الإلزامية: `HttpOnly; Secure; SameSite=Lax; Path=/`.
- يُصدر كوكي CSRF المرافق `__Host-aqar_csrf` بالخصائص: `Secure; SameSite=Strict; Path=/`.

## 3. حماية CSRF والتحقق من Origin
- جميع عمليات التعديل (`POST`, `PUT`, `PATCH`, `DELETE`) تخضع لطبقتَي تحقق إلزاميتين:
  1. فحص ترويسة `Origin` مقابل قائمة المصادر المسموح بها (`allowedOrigins`) بنمط `fail-closed`.
  2. مطابقة `X-CSRF-Token` مع كوكي `__Host-aqar_csrf` **ومع** `csrf_token_hash` المخزن في سجل الجلسة النشطة في `device_sessions`.

## 4. إدارة الجلسات وتدويرها وإبطالها
- تُفرض مدة خمول (30 دقيقة عبر `idle_timeout_at`) ومدة قصوى مطلقة (12 ساعة عبر `expires_at`).
- تُدوّر الجلسة ورمز CSRF تلقائياً عند المصادقة أو تغيير الأدوار والصلاحيات، مع إبطال الجلسة السابقة فوراً.
- عند تسجيل الخروج أو تعليق العضوية، تُبطل الجلسات المرتبطة فوراً في قاعدة البيانات.

## 5. Rate Limiting الموزع ومزود OTP
- يُطبق الحد على ثلاثة أبعاد متزامنة: الحساب (`identifier_hash`)، عنوان IP (`ip_hash`)، والجهاز (`device_id`).
- في الإنتاج يُستخدم جدول PostgreSQL المشترك `rate_limit_buckets` (`PgRateLimitStore`) أو Redis، ويُمنع تشغيل المخزن المحلي `InMemoryTestRateLimitStore` في `NODE_ENV=production`.
- إرسال OTP مفصول عبر واجهة `OtpDeliveryProvider`؛ المزود الافتراضي `UnconfiguredOtpProvider` يرفض العمل حتى اعتماد مزود حقيقي في القسم 15.
