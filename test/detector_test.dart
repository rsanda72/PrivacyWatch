import 'package:flutter_test/flutter_test.dart';
import 'package:privacywatch/core/app_blocker.dart';
import 'package:privacywatch/core/event.dart';
import 'package:privacywatch/core/pii_detector.dart';

void main() {
  final d = PiiDetector();
  Set<PiiCategory> cats(String s) => d.scan(s, 'body').map((m) => m.category).toSet();

  test('detects email, phone, ssn', () {
    expect(cats('a=john@example.com&p=555-123-4567&s=123-45-6789'),
        containsAll([PiiCategory.email, PiiCategory.phone, PiiCategory.ssn]));
  });

  test('card requires Luhn', () {
    expect(cats('4111 1111 1111 1111'), contains(PiiCategory.creditCard));
    expect(cats('4111 1111 1111 1112'), isNot(contains(PiiCategory.creditCard)));
  });

  test('redacts values', () {
    expect(d.scan('x@example.com', 'url').first.redacted, isNot(contains('example')));
  });

  test('severity: HTTP escalates, trackers are at least low', () {
    TransactionEvent ev(String how, String host, List<PiiMatch> what) =>
        TransactionEvent(time: DateTime.now(), who: host, what: what, how: how, destination: host);
    final email = d.scan('a@b.com', 'body');
    expect(ev('HTTPS tunnel', 'x.com', email).severity, Severity.medium);
    expect(ev('HTTP POST', 'x.com', email).severity, Severity.high);
    expect(ev('HTTPS tunnel', 'x.com', const []).severity, Severity.info);
    expect(ev('HTTPS tunnel', 'www.google-analytics.com', const []).severity, Severity.low);
  });

  test('blocker matches subdomains', () {
    final b = AppBlocker()..blockHost('example.com');
    expect(b.isHostBlocked('www.example.com'), isTrue);
    expect(b.isHostBlocked('notexample.com'), isFalse);
  });
}
