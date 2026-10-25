<script setup lang="ts">
import { computed } from 'vue';
import { RouterLink, useRouter } from 'vue-router';
import { ChevronRight, Info } from 'lucide-vue-next';
import Card from '@/components/ui/Card.vue';
import CardHeader from '@/components/ui/CardHeader.vue';
import CardContent from '@/components/ui/CardContent.vue';
import Score from '@/components/ui/Score.vue';
import FindingCard from '@/components/FindingCard.vue';
import OverallScore from '@/components/OverallScore.vue';
import AiPanel from '@/components/AiPanel.vue';
import AiSummaries from '@/components/AiSummaries.vue';
import { inBank, setBank, store } from '@/lib/store';
import { ACCESS_LABEL, LAYERS, LAYER_LABEL, LAYER_SHORT, accessOf } from '@/lib/utils';

const r = computed(() => store.report!);
const router = useRouter();
/** Bank name -> its summary page (the filter follows). */
function openBank(id: string) {
  setBank(id);
  router.push({ path: '/banks', query: { bank: id } });
}
const names = computed(() => Object.fromEntries(r.value.targets.map((t) => [t.id, t.name])));
const sevRank: Record<string, number> = { high: 0, medium: 1, low: 2, none: 3 };
// Bank filter (header picker): scorecard rows, tiles and top findings follow it; the access note stays global.
const targets = computed(() => r.value.targets.filter((t) => inBank(t.id)));
const top = computed(() =>
  r.value.findings
    .filter((f) => f.status === 'fail' && inBank(f.targetId))
    .sort((a, b) => sevRank[a.severity] - sevRank[b.severity])
    .slice(0, 6),
);
// Who was reached how, for the scope note. Order: deepest access first.
const ACCESS_ORDER = ['mock', 'full', 'sandbox', 'bis', 'pending', 'probes', 'spec'] as const;
const ACCESS_TEXT: Record<string, string> = {
  mock: 'Full flow on simulated data (payments, deposits, loans, negative tests)',
  full: 'Full flow in a test environment',
  sandbox: 'Real sandbox journey: mTLS, signed requests (GE-JWS), OAuth, headless bank login, account reads',
  bis: 'Proprietary API, read-only, with a registered test app',
  pending: 'Certificates requested; static spec checks and probes until they arrive',
  probes: 'Read-only, unauthenticated probes',
  spec: 'Published OpenAPI document only (no reachable sandbox)',
};
const ACCESS_SHORT: Record<string, string> = { mock: 'mock', full: 'full flow', sandbox: 'sandbox', bis: 'BIS', pending: 'awaiting certs', probes: 'probes', spec: 'spec only' };
const groups = computed(() =>
  ACCESS_ORDER.map((a) => ({ a, targets: r.value.targets.filter((t) => accessOf(t) === a) })).filter((g) => g.targets.length),
);
// Like-for-like: the same checks for every scored real bank, highest first.
const common = computed(() => {
  const c = r.value.common;
  if (!c) return null;
  const rows = c.targets.map((id) => ({ id, name: names.value[id] ?? id, score: c.scores[id] })).sort((a, b) => (b.score ?? -1) - (a.score ?? -1));
  return { n: c.checkIds.length, checkIds: c.checkIds, rows };
});
const sandboxCount = computed(() => r.value.targets.filter((t) => accessOf(t) === 'sandbox').length);
const tiles = computed(() => {
  if (store.bank === 'all')
    return [
      { label: 'Targets audited', value: r.value.targets.length },
      { label: 'API calls', value: r.value.totals.calls },
      { label: 'Failures', value: r.value.totals.failures },
      { label: 'Warnings', value: r.value.totals.warnings },
    ];
  const c = targets.value[0]?.counts ?? { pass: 0, fail: 0, warn: 0 };
  return [
    { label: 'Checks evaluated', value: targets.value[0]?.evaluated ?? 0 },
    { label: 'Passed', value: c.pass },
    { label: 'Failures', value: c.fail },
    { label: 'Warnings', value: c.warn },
  ];
});
</script>

<template>
  <div class="space-y-6">
    <div class="flex gap-3 rounded-xl border border-border bg-muted/60 p-4 text-sm">
      <Info class="mt-0.5 size-4 shrink-0 text-muted-foreground" />
      <div class="min-w-0 space-y-3">
        <p class="leading-relaxed">
          The organizers supplied only the <b>TBC mock API</b>. Access to real bank sandboxes was obtained by the Scio team directly
          from the banks<template v-if="sandboxCount"> ({{ sandboxCount }} so far)</template>: test certificates (QWAC for mTLS, QSealC for request signing)
          from developer portals or issued on request, plus the banks' test users.
        </p>
        <!-- Per-target access, collapsed so the scorecard stays near the top on phones. -->
        <details class="group">
          <summary class="flex cursor-pointer list-none items-center gap-1.5 py-1 text-xs font-medium [&::-webkit-details-marker]:hidden">
            <ChevronRight class="size-3.5 shrink-0 transition-transform group-open:rotate-90" />
            Access per target: {{ groups.map((g) => `${g.targets.length} ${ACCESS_SHORT[g.a]}`).join(' · ') }}
          </summary>
          <dl class="mt-2 grid gap-2 pl-5">
            <div v-for="g in groups" :key="g.a" class="min-w-0">
              <dt class="text-xs font-medium">{{ ACCESS_LABEL[g.a] }} <span class="font-normal text-muted-foreground">· {{ ACCESS_TEXT[g.a] }}</span></dt>
              <dd class="text-xs text-muted-foreground">{{ g.targets.map((t) => t.name).join(', ') }}</dd>
            </div>
          </dl>
        </details>
        <p class="text-xs leading-relaxed text-muted-foreground">
          Thresholds are <b class="text-foreground">{{ r.thresholds.source }}</b><template v-if="r.thresholds.source === 'assumed'"> until NBG indicators are confirmed</template>:
          availability ≥ {{ r.thresholds.availabilityPct }}%, p95 ≤ {{ r.thresholds.latencyP95Ms }} ms.
          Every check is mapped to the clause it enforces in
          <template v-for="(d, k) in r.standards?.documents ?? {}" :key="k"><template v-if="String(k).startsWith('GE') || k === 'BG-IG'"><a :href="d.url" target="_blank" rel="noopener" class="underline underline-offset-2" :title="d.title">{{ k }}</a>{{ ' ' }}</template></template>.
        </p>
      </div>
    </div>

    <div class="grid grid-cols-2 gap-3 md:grid-cols-4">
      <Card v-for="t in tiles" :key="t.label" class="p-4">
        <div class="text-xs text-muted-foreground">{{ t.label }}</div>
        <div class="mt-1 text-2xl font-semibold tabular-nums">{{ t.value }}</div>
      </Card>
    </div>

    <Card>
      <CardHeader title="Scorecard" :description="`Weighted share of checks passed per layer. Failures weigh by severity (high 3, medium 2, low 1); warnings count half. The number under each overall score is how many checks it rests on; targets with fewer than ${r.thresholds.minEvaluatedChecks} are not scored, and a layer with fewer than ${r.thresholds.minLayerChecks ?? 3} checks shows no score (reliability and latency use sample counts instead).`" />
      <!-- Small screens: one card per target with a score grid. -->
      <CardContent class="grid grid-cols-1 gap-3 lg:hidden">
        <div v-for="t in targets" :key="t.id" class="min-w-0 rounded-lg border border-border p-3">
          <div class="flex items-start justify-between gap-3">
            <div class="min-w-0">
              <button type="button" class="text-left font-medium leading-snug underline-offset-2 hover:underline" @click="openBank(t.id)">{{ t.name }}</button>
              <div class="mt-1 flex flex-wrap items-center gap-1.5 text-xs text-muted-foreground">
                <span class="rounded border border-border px-1">{{ ACCESS_LABEL[accessOf(t)] }}</span>
                <a v-if="t.source" :href="t.source" target="_blank" rel="noopener" class="underline underline-offset-2">source</a>
              </div>
            </div>
            <OverallScore class="shrink-0" :evaluated="t.evaluated" :overall="t.overall" :min="r.thresholds.minEvaluatedChecks" />
          </div>
          <div class="mt-1.5 truncate font-mono text-xs text-muted-foreground" :title="t.baseUrl">{{ t.baseUrl.replace(/^https?:\/\//, '') }}</div>
          <div class="mt-3 grid grid-cols-3 gap-2 text-center">
            <div v-for="l in LAYERS" :key="l" class="rounded-md bg-muted px-1 py-1.5">
              <div class="truncate text-[10px] text-muted-foreground" :title="LAYER_LABEL[l]">{{ LAYER_SHORT[l] }}</div>
              <Score :value="t.scores[l]" />
              <div v-if="t.layerChecks" class="text-[10px] tabular-nums text-muted-foreground">{{ t.layerChecks[l] }} chk</div>
            </div>
            <div class="rounded-md bg-muted px-1 py-1.5">
              <div class="text-[10px] text-muted-foreground">Fail / warn</div>
              <div class="text-sm tabular-nums">{{ t.counts.fail }} / {{ t.counts.warn }}</div>
            </div>
          </div>
          <p v-if="t.note" class="mt-2 line-clamp-3 text-xs text-muted-foreground" :title="t.note">{{ t.note }}</p>
        </div>
      </CardContent>
      <!-- lg and up: table; the column headers stick under the page header while scrolling. -->
      <CardContent class="hidden lg:block">
        <table class="w-full border-separate border-spacing-0 text-sm">
          <thead>
            <tr class="text-left text-xs text-muted-foreground">
              <th class="sticky top-[var(--header-h,57px)] z-10 border-b border-border bg-card py-2 pr-4 font-medium">Target</th>
              <th v-for="l in LAYERS" :key="l" class="sticky top-[var(--header-h,57px)] z-10 border-b border-border bg-card px-3 py-2 text-center font-medium">{{ LAYER_LABEL[l] }}</th>
              <th class="sticky top-[var(--header-h,57px)] z-10 border-b border-border bg-card px-3 py-2 text-center font-medium">Overall</th>
              <th class="sticky top-[var(--header-h,57px)] z-10 border-b border-border bg-card px-3 py-2 text-center font-medium whitespace-nowrap">Fail / warn</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="t in targets" :key="t.id" class="[&:not(:last-child)>td]:border-b [&>td]:border-border">
              <td class="py-3 pr-4">
                <button type="button" class="text-left font-medium underline-offset-2 hover:underline" title="Open the bank summary" @click="openBank(t.id)">{{ t.name }}</button>
                <div class="mt-0.5 flex flex-wrap items-center gap-1.5 text-xs text-muted-foreground">
                  <span class="rounded border border-border px-1">{{ ACCESS_LABEL[accessOf(t)] }}</span>
                  <span class="truncate font-mono">{{ t.baseUrl }}</span>
                  <a v-if="t.source" :href="t.source" target="_blank" rel="noopener" class="underline underline-offset-2">source</a>
                </div>
                <div v-if="t.note" class="mt-0.5 text-xs text-muted-foreground">{{ t.note }}</div>
              </td>
              <td v-for="l in LAYERS" :key="l" class="px-3 text-center">
                <Score :value="t.scores[l]" />
                <!-- How many verdicts the layer score rests on. -->
                <div v-if="t.layerChecks" class="text-[10px] tabular-nums text-muted-foreground">{{ t.layerChecks[l] }} chk</div>
              </td>
              <td class="px-3 text-center">
                <OverallScore class="!text-center" no-label :evaluated="t.evaluated" :overall="t.overall" :min="r.thresholds.minEvaluatedChecks" />
              </td>
              <td class="px-3 text-center whitespace-nowrap tabular-nums">{{ t.counts.fail }} / {{ t.counts.warn }}</td>
            </tr>
          </tbody>
        </table>
      </CardContent>
    </Card>

    <Card v-if="common && store.bank === 'all'">
      <CardHeader title="Like-for-like comparison" :description="`Overall scores rest on different check sets (the mock gets the full suite, a spec-only bank the static checks). This ranking scores every real bank on the same ${common.n} checks, the ones all of them received, each counted once (its worst result), so per-endpoint checks do not weigh more.`" />
      <CardContent>
        <ol class="grid gap-1.5 text-sm">
          <li v-for="(row, i) in common.rows" :key="row.id" class="flex items-center justify-between gap-3">
            <button type="button" class="min-w-0 truncate text-left underline-offset-2 hover:underline" @click="openBank(row.id)">{{ i + 1 }}. {{ row.name }}</button>
            <Score :value="row.score" />
          </li>
        </ol>
        <details class="mt-3 text-xs text-muted-foreground">
          <summary class="cursor-pointer">Checks used</summary>
          <p class="mt-1 font-mono leading-relaxed">{{ common.checkIds.join(' · ') }}</p>
        </details>
      </CardContent>
    </Card>

    <AiSummaries :r="r" :bank="store.bank" />

    <AiPanel v-if="r.ai" :ai="r.ai" />

    <div>
      <div class="mb-2 flex items-baseline justify-between">
        <h2 class="text-sm font-semibold">Most serious findings</h2>
        <RouterLink to="/findings" class="text-xs text-muted-foreground hover:text-foreground">All findings →</RouterLink>
      </div>
      <div class="grid gap-2">
        <FindingCard v-for="(f, i) in top" :key="i" :f="f" :target-name="names[f.targetId]" />
      </div>
    </div>
  </div>
</template>
