import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:privacywatch/core/app_blocker.dart';
import 'package:privacywatch/core/event.dart';
import 'package:privacywatch/core/pii_detector.dart';
import 'package:privacywatch/traffic_trend.dart';
import 'package:privacywatch/core/audit_store.dart';

void main() {
  test('audit snapshots persist and compare states', () {
    final dir = Directory.systemTemp.createTempSync('pw_audit');
    final f = File('${dir.path}/audit.json');
    final s = AuditStore.instance..attach(f);
    s.clearAll();
    final a = s.add(score: 60, requestsChecked: 5, blockedDestinations: 0, items: [
      AuditItem(host: 'ads.example', blocked: false, sent: 3, refused: 0, category: 'Advertising'),
      AuditItem(host: 'gone.example', blocked: false, sent: 1, refused: 0),
    ]);
    final b = s.add(score: 90, requestsChecked: 9, blockedDestinations: 1, items: [
      AuditItem(host: 'ads.example', blocked: true, sent: 3, refused: 2, category: 'Advertising'),
      AuditItem(host: 'new.example', blocked: false, sent: 2, refused: 0),
    ]);
    expect(a.id == b.id, isFalse);
    final d = AuditDiff(a, b);
    expect(d.newlyBlocked.map((i) => i.host), ['ads.example']);
    expect(d.newlySeenOpen.map((i) => i.host), ['new.example']);
    expect(d.notSeenAgain.map((i) => i.host), ['gone.example']);
    expect(d.scoreChange, 30);

    final copy = File('${dir.path}/other.json')..writeAsStringSync(f.readAsStringSync());
    s.attach(copy);
    expect(s.snapshots.length, 2);
    s.clearAll();
    expect(s.snapshots, isEmpty);
    dir.deleteSync(recursive: true);
  });

  test('traffic trend reports lower, higher, flat and too-little history', () {
    final t0 = DateTime(2026, 1, 1, 10);
    List<TrendPoint> series(int first, int second) => [
          TrendPoint(t0, first, false),
          TrendPoint(t0.add(const Duration(minutes: 4)), first, false),
          TrendPoint(t0.add(const Duration(minutes: 6)), second, false),
          TrendPoint(t0.add(const Duration(minutes: 10)), second, true),
        ];
    expect(TrafficTrend.compute(series(1000, 400)).verdict, TrendVerdict.positive);
    expect(TrafficTrend.compute(series(400, 1000)).verdict, TrendVerdict.negative);
    expect(TrafficTrend.compute(series(1000, 1050)).verdict, TrendVerdict.neutral);
    expect(TrafficTrend.compute([TrendPoint(t0, 5, false)]).verdict, TrendVerdict.notEnough);
  });

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

  test('blocks persist across restarts', () async {
    final dir = Directory.systemTemp.createTempSync('pw_test');
    final file = File('${dir.path}/blocks.json');
    final a = AppBlocker(storeFile: file)..blockHost('Example.com');
    a.apps['c:\\x\\tool.exe'] = BlockedApp('tool.exe', 'C:\\x\\tool.exe');
    a.blockHost('tracker.test'); // triggers a save including the app
    final b = AppBlocker(storeFile: file);
    await b.load(syncFirewall: false);
    expect(b.isHostBlocked('www.example.com'), isTrue);
    expect(b.isBlocked('tool.exe', 'C:\\x\\tool.exe'), isTrue);
    dir.deleteSync(recursive: true);
  });

  test('large block list survives load and save', () async {
    final dir = Directory.systemTemp.createTempSync('pw_big');
    final file = File('${dir.path}/blocks.json');
    final hosts = [for (var i = 0; i < 55; i++) 'host$i.example.com'];
    file.writeAsStringSync(jsonEncode({'apps': [], 'hosts': hosts}));
    final b = AppBlocker(storeFile: file);
    await b.load(syncFirewall: false);
    expect(b.hosts.length, 55);
    final again = AppBlocker(storeFile: file);
    await again.load(syncFirewall: false);
    expect(again.hosts.length, 55);
    dir.deleteSync(recursive: true);
  });

  test('every block change is written to the audit log', () {
    final dir = Directory.systemTemp.createTempSync('pw_audit');
    final b = AppBlocker(storeFile: File('${dir.path}/blocks.json'));
    b.blockHost('a.example.com');
    b.unblockHost('a.example.com');
    final log = File('${dir.path}/blocks.log').readAsStringSync();
    expect(log, contains('BLOCK host a.example.com'));
    expect(log, contains('UNBLOCK host a.example.com'));
    dir.deleteSync(recursive: true);
  });

  test('large bodies without matches scan quickly', () {
    final sw = Stopwatch()..start();
    PiiDetector().scan('blob=${'x' * 1000000}', 'body');
    PiiDetector().scan('1234567890' * 30000, 'body');
    expect(sw.elapsedMilliseconds, lessThan(3000));
  });
}
