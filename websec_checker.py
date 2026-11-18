import ssl
import certifi

from datetime import datetime
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse


HEADER_CHECKS = {
    "Content-Security-Policy": (
        "MEDIUM",
        "Add a Content-Security-Policy suited to the website's resources."
    ),
    "Strict-Transport-Security": (
        "MEDIUM",
        "After confirming HTTPS works, configure the Strict-Transport-Security header."
    ),
    "X-Content-Type-Options": (
        "LOW",
        "Set X-Content-Type-Options to nosniff."
    ),
    "X-Frame-Options": (
        "LOW",
        "Set X-Frame-Options to DENY or SAMEORIGIN, or use CSP frame-ancestors."
    ),
    "Referrer-Policy": (
        "LOW",
        "Set a Referrer-Policy suited to the website."
    ),
}


def add_finding(findings, severity, title, evidence, recommendation):
    findings.append({
        "severity": severity,
        "title": title,
        "evidence": evidence,
        "recommendation": recommendation,
    })


def check_cookies(headers, findings):
    cookies = headers.get_all("Set-Cookie") or []

    if not cookies:
        return 0

    for cookie in cookies:
        cookie_parts = cookie.split(";")
        cookie_name = cookie_parts[0].split("=", 1)[0].strip()

        attributes = {
            part.strip().split("=", 1)[0].lower()
            for part in cookie_parts[1:]
            if part.strip()
        }

        if "secure" not in attributes:
            add_finding(
                findings,
                "MEDIUM",
                f"Cookie '{cookie_name}' is missing Secure",
                "The Set-Cookie response does not include the Secure attribute.",
                "Add the Secure attribute so the cookie is sent only over HTTPS.",
            )

        if "httponly" not in attributes:
            add_finding(
                findings,
                "MEDIUM",
                f"Cookie '{cookie_name}' is missing HttpOnly",
                "The Set-Cookie response does not include the HttpOnly attribute.",
                "Add the HttpOnly attribute if the cookie does not need JavaScript access.",
            )

        if "samesite" not in attributes:
            add_finding(
                findings,
                "LOW",
                f"Cookie '{cookie_name}' is missing SameSite",
                "The Set-Cookie response does not include the SameSite attribute.",
                "Set an appropriate SameSite value, such as Lax or Strict.",
            )

    return len(cookies)


def format_finding(finding):
    return (
        f"[{finding['severity']}] {finding['title']}\n"
        f"  Evidence: {finding['evidence']}\n"
        f"  Recommendation: {finding['recommendation']}"
    )


def main():
    url = input("Enter the website URL to check: ").strip()

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    if not urlparse(url).netloc:
        print("Invalid URL. Example: https://example.com")
        return

    request = Request(
        url,
        headers={"User-Agent": "WebSecurityChecker/1.0"},
        method="GET",
    )

    ssl_context = ssl.create_default_context(
        cafile=certifi.where()
    )

    try:
        try:
            response = urlopen(
                request,
                timeout=10,
                context=ssl_context,
            )
        except HTTPError as error:
            response = error

        with response:
            final_url = response.geturl()
            headers = response.headers
            status_code = response.getcode()
            findings = []

            if final_url.startswith("https://"):
                print("\n[OK] HTTPS is being used.")
            else:
                print("[WARNING] The website did not redirect to HTTPS.")
                add_finding(
                    findings,
                    "MEDIUM",
                    "HTTPS was not reached",
                    f"The final URL is {final_url}",
                    "Configure HTTPS and redirect HTTP traffic to HTTPS.",
                )

            print("\nSecurity header checks:")

            for header, (severity, recommendation) in HEADER_CHECKS.items():
                if headers.get(header):
                    print(f"[PRESENT] {header}")
                else:
                    print(f"[MISSING] {header}")
                    add_finding(
                        findings,
                        severity,
                        f"Missing security header: {header}",
                        f"The response did not include the {header} header.",
                        recommendation,
                    )

            server = headers.get("Server")
            if server:
                print(f"\n[INFO] Server header: {server}")
                add_finding(
                    findings,
                    "INFO",
                    "Server header is present",
                    f"The response includes: Server: {server}",
                    "Review whether the server header reveals unnecessary technology details.",
                )

            cookie_count = check_cookies(headers, findings)
            if cookie_count:
                print(f"\n[INFO] Found {cookie_count} cookie(s).")
            else:
                print("\n[INFO] No cookies were found in this response.")

            print("\nFindings:")

            if findings:
                for finding in findings:
                    print(f"\n{format_finding(finding)}")
            else:
                print("[OK] No issues were found by these checks.")

            report_lines = [
                "WEB SECURITY CHECKER REPORT",
                f"Checked at: {datetime.now().astimezone().isoformat(timespec='seconds')}",
                f"Checked URL: {final_url}",
                f"HTTP status: {status_code}",
                "",
                "This is a basic passive configuration check. "
                "It does not prove that a website is exploitable and is not a full vulnerability assessment.",
                "",
                "FINDINGS",
            ]

            if findings:
                for finding in findings:
                    report_lines.append("")
                    report_lines.append(format_finding(finding))
            else:
                report_lines.append("No issues were found by these checks.")

            report_path = Path(__file__).resolve().parent / "scan_report.txt"
            report_path.write_text(
                "\n".join(report_lines),
                encoding="utf-8",
            )

            print(f"\nReport saved to: {report_path}")

    except (URLError, TimeoutError, OSError) as error:
        print(f"\nCould not connect to the website: {error}")


if __name__ == "__main__":
    main()