# 🛡️ Domain & Web Security Verification Tool

أداة وسكربت برمجي مبني بلغة Python لفحص وتأكيد صحة وأمان النطاقات والمواقع الإلكترونية (Domains)، والتحقق من شهادات الأمان SSL وإعدادات الـ DNS.

---

## 🚀 الميزات الرئيسية (Features)

- **فحص شهادات الأمان (SSL/TLS Check):** التحقق من صلاحية شهادة الأمان، تاريخ الانتهاء، والمشفر المعتمد.
- **التحقق من إعدادات الـ DNS:** جلب وتدقيق سجلات A, AAAA, MX, و TXT للنطاق.
- **فحص استجابة الخادم (HTTP Headers):** التحقق من وجود رؤوس الأمان التلقائية (Security Headers) مثل HSTS و X-Frame-Options.
- **توليد تقرير أمان:** طباعة أو حفظ تقرير دقيق حول حالة أمان الموقع.

---

## 🛠️ التقنيات المستخدمة (Tech Stack)

- **Language:** Python 3.x
- **Libraries:** `requests`, `socket`, `ssl`, `dnspython`
- **Networking Concepts:** TCP/IP, DNS Lookup, SSL Certificate Handshake, HTTP/HTTPS Protocols

---

## 📋 كيفية التشغيل (Usage)

1. استคลون المستودع:
```bash
git clone [https://github.com/rebhi-mahmoud-it/domain-security-checker.git](https://github.com/rebhi-mahmoud-it/domain-security-checker.git)
cd domain-security-checker# domain-security-checker
