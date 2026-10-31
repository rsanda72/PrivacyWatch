/// Personal-data categories as commonly defined in privacy policies (GDPR/CCPA).
enum Severity {
  info('Info', 0),
  low('Low', 1),
  medium('Medium', 2),
  high('High', 3),
  critical('Critical', 4);

  const Severity(this.label, this.rank);
  final String label;
  final int rank;

  /// Plain-language meaning and suggested response for this level.
  String get guidance => switch (this) {
        Severity.critical =>
          'Act now. Data that can cause financial loss or account takeover left this device. Block the app, then change any affected passwords or contact your bank.',
        Severity.high =>
          'Serious. Sensitive personal data was sent. Check whether you expected this app to have it; if not, block it and review its permissions.',
        Severity.medium =>
          'Worth a look. Ordinary identifying data was sent. This is common and often legitimate (a login, a delivery form), but if the recipient is unfamiliar or the app has no reason to know it, block or uninstall it.',
        Severity.low =>
          'Usually harmless on its own (for example your IP address, which every site sees). Only a concern if it repeats a lot or goes to unknown or ad companies.',
        Severity.info => 'No personal data seen. Normal background traffic.',
      };
}

enum PiiCategory {
  email('Email address', Severity.medium,
      'Directly identifies a person; used for tracking, profiling and spam.'),
  phone('Phone number', Severity.medium,
      'Directly identifies a person; enables contact, tracking and SIM-swap attacks.'),
  ssn('Government ID (SSN)', Severity.critical,
      'Sensitive identifier; enables identity theft. Should never be sent unencrypted.'),
  creditCard('Payment card', Severity.critical,
      'Financial data (PCI-DSS scope); enables fraud if intercepted.'),
  ipAddress('IP address', Severity.low,
      'Treated as personal data under GDPR; reveals approximate location and network.'),
  location('Geolocation', Severity.high,
      'Precise location reveals home, work and movement patterns.'),
  deviceId('Device / advertising ID', Severity.medium,
      'Persistent identifier used to track you across apps and sites.'),
  credential('Credential / token', Severity.critical,
      'Password, API key or session token; allows account takeover.'),
  dob('Date of birth', Severity.high,
      'Identity-verification data; combined with other fields enables identity theft.');

  const PiiCategory(this.label, this.severity, this.explanation);
  final String label;
  final Severity severity;
  final String explanation;

  /// What to ask yourself, and what to do, when this type of data is found.
  String get advice => switch (this) {
        PiiCategory.email =>
          'Expected if you are signing in, subscribing or checking out on that site. Unexpected if it goes to an ad or tracking company: that links your identity to your browsing. Consider blocking that destination.',
        PiiCategory.phone =>
          'Fine for a service you gave it to (delivery, 2-step login). If an ad or analytics firm receives it, it can be matched to you across services. Block that destination if unexpected.',
        PiiCategory.ssn =>
          'Should only go to an official, encrypted service you chose. Block immediately if unexpected and consider a credit freeze if it was sent unencrypted.',
        PiiCategory.creditCard =>
          'Only acceptable to a payment page over HTTPS that you used. Anything else: block the app, check your card statement and tell your bank.',
        PiiCategory.ipAddress =>
          'Every server you contact sees your IP, so this is normal. Only matters if sent inside data to third parties, or if it is the only thing sent repeatedly to an ad network.',
        PiiCategory.location =>
          'Fine for a map or weather app you are using. Unexpected otherwise: revoke the app\'s location permission and block it.',
        PiiCategory.deviceId =>
          'This is the ID advertisers use to follow you between apps. Reset or disable your advertising ID in system settings and block the recipient if it is an ad network.',
        PiiCategory.credential =>
          'A secret was sent. Normal only when you are logging in to that service over HTTPS. If it was plain HTTP or went elsewhere, change the password or revoke the key now.',
        PiiCategory.dob =>
          'Normal for age or identity checks you started. Unexpected elsewhere: block the recipient and review what the app asked for.',
      };
}

class PiiMatch {
  PiiMatch(this.category, this.redacted, this.where);
  final PiiCategory category;
  final String redacted; // never store the raw value
  final String where; // url, header:<name>, body
}

class PiiDetector {
  static final _rules = <PiiCategory, RegExp>{
    PiiCategory.email: RegExp(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'),
    PiiCategory.phone: RegExp(r'(?<!\d)(?:\+?1[ -.]?)?\(?\d{3}\)?[ -.]\d{3}[ -.]\d{4}(?!\d)'),
    PiiCategory.ssn: RegExp(r'(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)'),
    PiiCategory.creditCard: RegExp(r'(?<!\d)(?:\d[ -]?){13,19}(?!\d)'),
    PiiCategory.ipAddress: RegExp(r'(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)'),
    PiiCategory.location: RegExp(
        r'(?:lat|latitude)=-?\d{1,3}\.\d{3,}.{0,20}(?:lon|lng|longitude)=-?\d{1,3}\.\d{3,}',
        caseSensitive: false),
    PiiCategory.deviceId: RegExp(
        r'(?:idfa|gaid|advertising_?id|device_?id|android_?id)=?[:"= ]*[0-9a-fA-F-]{16,36}',
        caseSensitive: false),
    PiiCategory.credential:
        RegExp(r'(?:password|passwd|pwd|token|api[_-]?key|secret)["\s:=]+[^\s&",]{4,}', caseSensitive: false),
    PiiCategory.dob: RegExp(r'(?:dob|birth_?date|date_?of_?birth)["\s:=]+\d{1,4}[-/]\d{1,2}[-/]\d{1,4}',
        caseSensitive: false),
  };

  static bool _luhn(String digits) {
    var sum = 0, alt = false;
    for (var i = digits.length - 1; i >= 0; i--) {
      var n = digits.codeUnitAt(i) - 48;
      if (alt) {
        n *= 2;
        if (n > 9) n -= 9;
      }
      sum += n;
      alt = !alt;
    }
    return sum % 10 == 0;
  }

  static bool _validIp(String s) => s.split('.').every((p) => int.parse(p) <= 255);

  static String _redact(String v) {
    if (v.length <= 4) return '****';
    return '${v.substring(0, 2)}***${v.substring(v.length - 2)}';
  }

  List<PiiMatch> scan(String text, String where) {
    final out = <PiiMatch>[];
    _rules.forEach((cat, re) {
      for (final m in re.allMatches(text)) {
        final v = m.group(0)!;
        if (cat == PiiCategory.creditCard) {
          final d = v.replaceAll(RegExp(r'[ -]'), '');
          if (d.length < 13 || !_luhn(d)) continue;
        }
        if (cat == PiiCategory.ipAddress && !_validIp(v)) continue;
        out.add(PiiMatch(cat, _redact(v), where));
      }
    });
    return out;
  }
}
