import socket
import ssl
import requests
import datetime
import urllib.parse


def check_ssl_certificate(hostname):
    """فحص واستخراج معلومات شهادة SSL/TLS للموقع"""
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                
                # استخراج تاريخ الانتهاء
                exp_date_str = cert['notAfter']
                exp_date = datetime.datetime.strptime(exp_date_str, "%b %d %H:%M:%S %Y %Z")
                days_left = (exp_date - datetime.datetime.utcnow()).days
                
                # استخراج جهة الإصدار
                issuer = dict(x[0] for x in cert['issuer']).get('organizationName', 'غير معروف')
                
                return {
                    "valid": True,
                    "issuer": issuer,
                    "expires_on": exp_date.strftime("%Y-%m-%d"),
                    "days_remaining": days_left
                }
    except Exception as e:
        return {"valid": False, "error": str(e)}


def check_http_security_headers(url):
    """فحص وجود رؤوس الأمان الأساسية في استجابة HTTP"""
    headers_to_check = [
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Content-Security-Policy"
    ]
    try:
        response = requests.get(url, timeout=5, allow_redirects=True)
        results = {}
        for header in headers_to_check:
            results[header] = response.headers.get(header, "⚠️ غير مفعل")
        return results
    except Exception as e:
        return {"error": str(e)}


def analyze_domain(domain):
    """التأكد من أمان وصحة النطاق والموقع"""
    print(f"\n==========================================")
    print(f"🔍 فحص النطاق: {domain}")
    print(f"==========================================")
    
    # تنظيف اسم النطاق
    clean_domain = domain.replace("https://", "").replace("http://", "").split('/')[0]
    
    # 1. فحص SSL
    print("\n🔒 [1] فحص شهادة الأمان (SSL/TLS Certificate):")
    ssl_info = check_ssl_certificate(clean_domain)
    if ssl_info.get("valid"):
        print(f"   ✔️ جهة الإصدار: {ssl_info['issuer']}")
        print(f"   📅 تاريخ الانتهاء: {ssl_info['expires_on']}")
        print(f"   ⏳ الأيام المتبقية: {ssl_info['days_remaining']} يوم")
    else:
        print(f"   ❌ خطأ أو شهادة غير مفعّلة: {ssl_info.get('error')}")
        
    # 2. فحص HTTP Headers
    print("\n🌐 [2] فحص رؤوس أمان الخادم (Security Headers):")
    target_url = f"https://{clean_domain}"
    header_info = check_http_security_headers(target_url)
    if "error" not in header_info:
        for header, status in header_info.items():
            print(f"   • {header}: {status}")
    else:
        print(f"   ❌ تعذر الاتصال بالخادم: {header_info['error']}")

    print("\n==========================================\n")


if __name__ == "__main__":
    test_domain = input("أدخل اسم النطاق المراد فحصه (مثال: google.com): ").strip()
    if test_domain:
        analyze_domain(test_domain)
