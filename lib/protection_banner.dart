import 'package:flutter/material.dart';

import 'consumer_summary.dart';

/// Hero banner: animated shield, protection state, blocked count and per-data-type checks.
class ProtectionBanner extends StatefulWidget {
  const ProtectionBanner(this.s, {super.key});
  final ConsumerSummary s;

  @override
  State<ProtectionBanner> createState() => _ProtectionBannerState();
}

class _ProtectionBannerState extends State<ProtectionBanner> with SingleTickerProviderStateMixin {
  late final AnimationController _c =
      AnimationController(vsync: this, duration: const Duration(seconds: 3))..repeat(reverse: true);

  @override
  void dispose() {
    _c.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final s = widget.s;
    final th = Theme.of(context).textTheme;
    SafetyLevel level(String title) => s.items.firstWhere((i) => i.title == title).level;
    final worst = s.items.map((i) => i.level.index).fold(0, (a, b) => a > b ? a : b);
    final (label, color) = switch (worst) {
      0 => ('PROTECTED', Colors.green.shade600),
      1 => ('MOSTLY PROTECTED', Colors.amber.shade700),
      _ => ('ATTENTION NEEDED', Colors.red.shade700),
    };
    final t = s.tracking;
    final blocked = t.trackers + t.telemetry + t.advertising;

    Widget check(String text, SafetyLevel l) {
      final (icon, c) = switch (l) {
        SafetyLevel.safe => (Icons.check_circle, Colors.green.shade600),
        SafetyLevel.warning => (Icons.error_outline, Colors.amber.shade800),
        SafetyLevel.alert => (Icons.warning_amber_rounded, Colors.red.shade700),
      };
      return Padding(
        padding: const EdgeInsets.symmetric(vertical: 2),
        child: Row(mainAxisSize: MainAxisSize.min, children: [
          Icon(icon, color: c, size: 20),
          const SizedBox(width: 8),
          Text(l == SafetyLevel.safe ? '$text Protected' : '$text - review below', style: th.bodyLarge),
        ]),
      );
    }

    return Card(
      clipBehavior: Clip.antiAlias,
      color: color.withValues(alpha: 0.10),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Wrap(
          alignment: WrapAlignment.center,
          crossAxisAlignment: WrapCrossAlignment.center,
          spacing: 24,
          runSpacing: 12,
          children: [
            AnimatedBuilder(
              animation: _c,
              builder: (_, child) => Container(
                decoration: BoxDecoration(shape: BoxShape.circle, boxShadow: [
                  BoxShadow(color: color.withValues(alpha: 0.25 + 0.35 * _c.value), blurRadius: 12 + 24 * _c.value),
                ]),
                child: Transform.scale(scale: 0.96 + 0.06 * _c.value, child: child),
              ),
              child: ClipOval(child: Image.asset('icons/shield_for_PrivacyWatch.jpg', width: 140, height: 140, fit: BoxFit.cover)),
            ),
            Column(crossAxisAlignment: CrossAxisAlignment.start, mainAxisSize: MainAxisSize.min, children: [
              Text(label, style: th.headlineMedium?.copyWith(color: color, fontWeight: FontWeight.w900, letterSpacing: 2)),
              const SizedBox(height: 4),
              Text('$blocked Tracking Attempts Blocked', style: th.titleMedium),
              const SizedBox(height: 8),
              check('Passwords', level('Passwords')),
              check('Credit Cards', level('Credit cards')),
              check('Email', level('Email addresses')),
              check('Documents', level('Personal documents')),
              const SizedBox(height: 8),
              Text(worst == 0 ? 'PrivacyWatch actively monitored\nand protected your device.' : 'PrivacyWatch is monitoring. See the details below.',
                  style: th.bodyMedium),
            ]),
          ],
        ),
      ),
    );
  }
}
