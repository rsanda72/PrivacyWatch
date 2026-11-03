import 'core/ack_store.dart';
import 'core/event.dart';
import 'core/pii_detector.dart';

/// One line of evidence: found (true) or looked for but not observed (false).
class Clue {
  const Clue(this.found, this.text);
  final bool found;
  final String text;
  String get line => '${found ? '✓' : '✗'} $text';
}

enum RecommendedAction {
  monitor('Monitor'),
  watchClosely('Watch Closely'),
  restrict('Restrict'),
  block('Block'),
  immediate('Immediate Action Required');

  const RecommendedAction(this.label);
  final String label;
}

enum Impact {
  none('None'),
  low('Low'),
  medium('Medium'),
  high('High'),
  unknown('Unknown');

  const Impact(this.label);
  final String label;
}

/// Why PrivacyWatch reached its conclusion about one kind of finding from one app to one destination.
class Reasoning {
  Reasoning({
    required this.category,
    required this.app,
    required this.host,
    required this.blocked,
    required this.raw,
    required this.evidence,
    required this.context,
    required this.confidence,
    required this.assessment,
    required this.action,
    required this.recommendation,
    required this.impact,
    required this.impactText,
    required this.why,
    this.unencrypted = false,
  });

  final bool unencrypted; // sent over plain HTTP
  List<String> rawLines = const []; // raw transactions behind this finding

  final RecommendedAction recommendation;
  final Impact impact;
  final String impactText; // what may happen if the user blocks this traffic
  final List<String> why; // "Why this action was recommended"

  final PiiCategory category;
  final String app;
  final String host;
  final bool blocked; // every matching request was stopped
  final String raw;
  final List<Clue> evidence;
  final List<Clue> context;
  final int confidence; // 0-100
  final String assessment;
  final String action;

  String get confidenceBand => confidence >= 76 ? 'High' : confidence >= 51 ? 'Medium' : 'Low';

  /// 0-25 Informational, 26-50 Low, 51-75 Medium, 76-90 High, 91-100 Critical.
  Severity get severity => confidence >= 91
      ? Severity.critical
      : confidence >= 76
          ? Severity.high
          : confidence >= 51
              ? Severity.medium
              : confidence >= 26
                  ? Severity.low
                  : Severity.info;

  /// One plain sentence on what this means for the user.
  String get summaryLine => blocked
      ? 'Stopped before it left your device.'
      : 'Your ${(ReasoningEngine._noun[category] ?? 'personal data').replaceFirst('a ', '').replaceFirst('an ', '')} may have been sent to $host by $app.';

  String get ackKey => AckStore.key(category.name, app, host);

  /// Medium or above and actually sent: the kind of finding that should be acknowledged.
  bool get isActive => !blocked && !AckStore.instance.has(ackKey);

  bool get needsAttention => !blocked && confidence >= 51;

  String get title => '${category.label} - $app';

  String toText() => [
        '--------------------------------------------------',
        'WHY PRIVACYWATCH REACHED THIS CONCLUSION',
        '--------------------------------------------------',
        '',
        'Raw Detection:',
        raw,
        '',
        'Detection Evidence:',
        ...evidence.map((c) => c.line),
        '',
        'Context Analysis:',
        ...context.map((c) => c.line),
        '',
        'Confidence:',
        '$confidence% ($confidenceBand)',
        '',
        'Assessment:',
        assessment,
        '',
        'Recommended Action:',
        recommendation.label,
        action,
        '',
        'Functional Impact:',
        impact.label,
        impactText,
        '',
        'Why this action was recommended:',
        ...why.map((w) => '- $w'),
        '--------------------------------------------------',
      ].join('\n');
}

class ReasoningEngine {
  static const _paymentWords = ['checkout', 'payment', 'billing', 'cart', 'purchase', 'card', 'pay'];
  static const _loginWords = ['login', 'signin', 'sign-in', 'auth', 'oauth', 'session', 'account', 'token'];
  static const _profileWords = ['signup', 'register', 'profile', 'account', 'contact', 'subscribe', 'order', 'checkout'];

  static const _noun = {
    PiiCategory.creditCard: 'a payment card number',
    PiiCategory.credential: 'a password or sign-in token',
    PiiCategory.email: 'an email address',
    PiiCategory.phone: 'a phone number',
    PiiCategory.ssn: 'a government ID number',
    PiiCategory.dob: 'a date of birth',
  };

  static const _base = {
    PiiCategory.creditCard: 30,
    PiiCategory.credential: 35,
    PiiCategory.ssn: 30,
    PiiCategory.dob: 35,
    PiiCategory.email: 45,
    PiiCategory.phone: 35,
  };

  static bool _hasWord(String s, List<String> words) {
    final l = s.toLowerCase();
    return words.any(l.contains);
  }

  static String _appStem(String app) =>
      app.toLowerCase().replaceAll(RegExp(r'\.exe$'), '').replaceAll(RegExp(r'[^a-z0-9]'), '');

  static bool _isFinding(PiiCategory c) => _base.containsKey(c);

  /// Explains every sensitive finding, one entry per kind of data, app and destination.
  static List<Reasoning> analyzeAll(List<TransactionEvent> events, bool Function(TransactionEvent) wasBlocked) {
    final groups = <String, List<TransactionEvent>>{};
    final cats = <String, PiiCategory>{};
    for (final e in events) {
      for (final c in e.what.map((m) => m.category).toSet().where(_isFinding)) {
        final key = '${c.name}|${e.app ?? ''}|${e.host}';
        groups.putIfAbsent(key, () => []).add(e);
        cats[key] = c;
      }
    }
    final out = [
      for (final g in groups.entries)
        analyze(cats[g.key]!, g.value, wasBlocked, all: events)
          ..rawLines = [for (final e in g.value.take(25)) '${e.time.toIso8601String()} | ${e.how} | ${e.destination}']
    ];
    out.sort((a, b) => b.confidence.compareTo(a.confidence));
    return out;
  }

  static Reasoning analyze(PiiCategory c, List<TransactionEvent> evs, bool Function(TransactionEvent) wasBlocked,
      {List<TransactionEvent> all = const []}) {
    final matches = [for (final e in evs) ...e.what.where((m) => m.category == c)];
    final first = evs.first;
    final app = (first.app ?? 'an unknown app').replaceAll(RegExp(r' \(PID \d+\)'), '');
    final host = first.host;
    final blocked = evs.every(wasBlocked);
    final others = {for (final e in evs) ...e.what.map((m) => m.category)}..remove(c)..remove(PiiCategory.ipAddress);
    final url = evs.map((e) => '${e.destination} ${e.who}').join(' ');
    final hasBody = evs.any((e) => e.how.contains('with body'));
    final stem = _appStem(app);
    final ownService = stem.length >= 4 && host.toLowerCase().replaceAll('-', '').contains(stem);
    final tracker = first.tracker;

    var score = _base[c]!;
    var support = 0; // independent indicators beyond the pattern itself
    final evidence = <Clue>[Clue(true, 'Matched the known format of ${_noun[c]}')];
    final context = <Clue>[];

    void ev(bool found, String yes, String no, int delta, {bool counts = true}) {
      evidence.add(Clue(found, found ? yes : no));
      if (found) {
        score += delta;
        if (counts) support++;
      }
    }

    void cx(bool found, String yes, String no, int delta, {bool counts = true}) {
      context.add(Clue(found, found ? yes : no));
      if (found) {
        score += delta;
        if (counts && delta > 0) support++;
      }
    }

    if (c == PiiCategory.creditCard) {
      ev(true, 'Passed payment card checksum validation', '', 15);
    }
    final inForm = matches.any((m) => m.where == 'body');
    final headerNames = {
      for (final m in matches.where((m) => m.where.startsWith('header:'))) m.where.substring(7)
    };
    final paymentHeader = headerNames.any((h) => _hasWord(h, _paymentWords));
    if (inForm) {
      ev(true, 'Found inside submitted form data', '', 10);
    } else if (paymentHeader) {
      ev(true, 'Found in a header named like a payment field', '', 5);
    } else {
      evidence.add(Clue(false, headerNames.isNotEmpty
          ? 'Found only in a technical header (${headerNames.take(2).join(', ')}), not a payment field'
          : 'Only appeared in a web address, which is less typical for real submissions'));
      score -= 10;
    }

    // The same value going unchanged to several unrelated destinations points to a fixed identifier.
    final sameHosts = {
      for (final e in all)
        if (e.app == first.app && e.what.any((m) => m.category == c && matches.any((x) => x.redacted == m.redacted)))
          e.host
    };
    final routine = _hasWord(url, ['captive', 'check_network', 'hotspot', 'generate_204', 'connectivity', 'ncsi', 'heartbeat']);

    switch (c) {
      case PiiCategory.creditCard:
        final billing = others.any((o) => o == PiiCategory.email || o == PiiCategory.phone || o == PiiCategory.dob);
        cx(_hasWord(url, _paymentWords), 'Destination looks like a checkout or payment page',
            'No checkout or payment activity observed', 20);
        cx(billing, 'Billing-style details (such as name or contact information) were sent alongside',
            'No billing-related fields detected', 10);
        cx(false, '', 'No security code (CVV) detected', 0);
        cx(false, '', 'No expiration date detected', 0);
      case PiiCategory.credential:
        cx(_hasWord(url, _loginWords), 'Destination looks like a sign-in request', 'No sign-in activity observed', 20);
        cx(others.contains(PiiCategory.email), 'A username or email was sent alongside it',
            'No username detected alongside it', 15);
        cx(hasBody, 'Sent as a form submission', 'Not sent as a form submission', 5, counts: false);
      default:
        cx(_hasWord(url, _profileWords), 'Destination looks like a sign-up, account or order page',
            'No sign-up, account or order activity observed', 10);
        cx(others.isNotEmpty, 'Combined with other personal details (${others.map((o) => o.label.toLowerCase()).take(2).join(', ')})',
            'Not combined with other personal details', 15);
    }

    context.insert(0, Clue(true, 'Request attributed to $app'));
    if (ownService) {
      cx(true, 'Destination ($host) appears to belong to the same company as $app',
          '', -15);
    }
    if (tracker != null) {
      cx(true, 'Destination is a known ${tracker.category.toLowerCase()} service (${tracker.owner})', '', 15);
    }
    if (routine) {
      cx(true, 'Request looks like a routine network or connectivity check', '', -25, counts: false);
    }
    if (sameHosts.length >= 2) {
      cx(true, 'The same value was sent unchanged to ${sameHosts.length} different destinations, which suggests a fixed identifier rather than a real ${c.label.toLowerCase()}',
          '', -15, counts: false);
    }
    if (!hasBody && !inForm && !paymentHeader) {
      cx(true, 'Request carried no form data, which looks more like routine background traffic', '', -10, counts: false);
    }
    if (!first.encrypted && !blocked) {
      context.add(const Clue(true, 'Connection was not encrypted, so others on the network could have seen it'));
    }

    // Critical needs several independent indicators; a pattern match alone can never reach it.
    var conf = score.clamp(5, 97);
    if (conf >= 91 && support < 3) conf = 85;

    final band = conf >= 76 ? 'High' : conf >= 51 ? 'Medium' : 'Low';
    final what = _noun[c]!;
    final assessment = blocked
        ? 'Based on all available evidence, this looked like $what ($band confidence), but PrivacyWatch stopped it before it left your device.'
        : conf >= 76
            ? 'Additional analysis found several signs that $what was really sent to $host. This increased confidence because the surrounding activity matches how real ${c == PiiCategory.credential ? 'sign-ins' : 'submissions'} look.'
            : conf >= 51
                ? 'Based on all available evidence, this may be $what, but some supporting signs are missing, so it is not confirmed.'
                : 'Although the detected value resembles $what, the surrounding evidence suggests it is more likely an app-generated identifier or ordinary data than the real thing. Missing signs reduced confidence.';
    // Functional impact of blocking: how much the app likely relies on this destination.
    final userFlow = _hasWord(url, _paymentWords) || _hasWord(url, _loginWords);
    final (impact, impactText) = tracker != null
        ? (Impact.none, 'Blocking should not change how $app works. This destination is a ${tracker.category.toLowerCase()} service, not part of the app itself.')
        : ownService
            ? (Impact.high, 'Blocking may stop parts of $app from working, because $host appears to be its own service.')
            : userFlow
                ? (Impact.medium, 'Blocking may stop a sign-in or payment you are trying to complete.')
                : !hasBody
                    ? (Impact.low, 'Blocking is unlikely to be noticed. This looks like routine background traffic.')
                    : (Impact.unknown, 'We are not sure what $host does for $app. Blocking may or may not affect it.');

    // Least disruptive action that fits the evidence; blocking is never recommended from a pattern match alone.
    final confirmed = conf >= 95 && support >= 4;
    var rec = blocked
        ? RecommendedAction.monitor
        : confirmed
            ? RecommendedAction.immediate
            : conf >= 91
                ? RecommendedAction.block
                : conf >= 76
                    ? RecommendedAction.restrict
                    : conf >= 51
                        ? RecommendedAction.watchClosely
                        : RecommendedAction.monitor;
    if (rec == RecommendedAction.block && impact == Impact.high) rec = RecommendedAction.restrict;

    final action = switch (rec) {
      _ when blocked => 'No action needed. It was already blocked.',
      RecommendedAction.monitor => 'No immediate action required. PrivacyWatch will keep watching.',
      RecommendedAction.watchClosely => 'Take a quick look. If you recognise $app and $host, you can ignore this.',
      RecommendedAction.restrict =>
        'Check that you expected $app to send this to $host. If not, limit it (block just that destination) rather than the whole app.',
      RecommendedAction.block => 'Block $host. The evidence is strong and blocking is unlikely to cost you much.',
      RecommendedAction.immediate =>
        'Act now: block $host${c == PiiCategory.creditCard ? ', check your card statement and tell your bank if anything looks wrong.' : c == PiiCategory.credential ? ' and change the affected password.' : '.'}',
    };

    final why = <String>[
      if (blocked)
        'It was already stopped, so there is nothing further to do except keep watching.'
      else if (conf < 51)
        'Pattern matching alone is insufficient to confirm data exposure.'
      else if (conf < 76)
        'Some supporting evidence was found, but not enough to confirm anything.'
      else
        'Several independent signs point the same way, which increased confidence.',
      if (ownService && !blocked) 'Additional analysis reduced confidence because the traffic goes to the same company as the app.',
      if (!blocked && rec == RecommendedAction.monitor) 'Monitoring is recommended while more evidence is collected.',
      if (impact == Impact.high || impact == Impact.medium) 'Blocking may affect application functionality.',
      if (rec == RecommendedAction.restrict && impact == Impact.high && conf >= 91)
        'We chose the least disruptive option instead of a full block because the app may depend on this destination.',
    ];

    return Reasoning(
      category: c,
      app: app,
      host: host,
      blocked: blocked,
      raw: 'A value matched the pattern of $what.',
      evidence: evidence.where((e) => e.text.isNotEmpty).toList(),
      context: context.where((e) => e.text.isNotEmpty).toList(),
      confidence: conf,
      assessment: assessment,
      action: action,
      recommendation: rec,
      impact: impact,
      impactText: impactText,
      why: why,
      unencrypted: !first.encrypted && !blocked,
    );
  }
}
