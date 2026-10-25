<script setup lang="ts">
import { computed, ref } from 'vue';
import type { EndpointStats } from '@/lib/api';

/** Grouped bars: p50 and p95 per endpoint, with the p95 threshold as a reference line. */
// p95/p99 are only drawn with enough samples; below minSamples they equal the slowest call.
const props = withDefaults(defineProps<{ stats: EndpointStats[]; threshold: number; minSamples?: number }>(), { minSamples: 20 });
const enough = (s: EndpointStats) => s.samples >= props.minSamples;

const W = 640, H = 240, M = { t: 16, r: 16, b: 40, l: 48 };
const iw = W - M.l - M.r, ih = H - M.t - M.b;

const maxV = computed(() => {
  const m = Math.max(props.threshold, ...props.stats.map((s) => (enough(s) ? s.p95 : s.p50)));
  const step = m > 2000 ? 1000 : m > 1000 ? 500 : m > 400 ? 200 : 100;
  return Math.ceil((m * 1.1) / step) * step;
});
const ticks = computed(() => {
  const n = 4;
  return Array.from({ length: n + 1 }, (_, i) => Math.round((maxV.value / n) * i));
});
const y = (v: number) => M.t + ih - (v / maxV.value) * ih;
const group = computed(() => iw / Math.max(1, props.stats.length));
const barW = computed(() => Math.min(28, (group.value - 24) / 2));

const series = [
  { key: 'p50' as const, label: 'p50', color: 'var(--series-1)' },
  { key: 'p95' as const, label: 'p95', color: 'var(--series-2)' },
];

function barPath(x: number, v: number, w: number) {
  const top = y(v), base = M.t + ih, r = Math.min(4, w / 2, base - top);
  return `M${x},${base} V${top + r} Q${x},${top} ${x + r},${top} H${x + w - r} Q${x + w},${top} ${x + w},${top + r} V${base} Z`;
}

const hover = ref<{ i: number; x: number; y: number } | null>(null);
const root = ref<HTMLElement | null>(null);
// Position relative to the chart container (offsetX on SVG children is unreliable).
function onMove(e: MouseEvent, i: number) {
  const box = root.value?.getBoundingClientRect();
  if (box) hover.value = { i, x: e.clientX - box.left, y: e.clientY - box.top };
}
const showTable = ref(false);
</script>

<template>
  <div ref="root" class="relative">
    <div class="mb-3 flex flex-wrap items-center gap-x-4 gap-y-1.5 text-xs text-muted-foreground">
      <span v-for="s in series" :key="s.key" class="inline-flex items-center gap-1.5 whitespace-nowrap"><span class="inline-block size-2.5 rounded-sm" :style="{ background: s.color }" />{{ s.label }}<span class="hidden sm:inline"> response time</span></span>
      <span class="inline-flex items-center gap-1.5 whitespace-nowrap"><span class="inline-block w-4 border-t-2 border-dashed border-muted-foreground" />threshold {{ threshold }} ms</span>
      <button class="ml-auto -my-1 rounded px-1 py-1 whitespace-nowrap underline-offset-2 hover:underline" @click="showTable = !showTable">{{ showTable ? 'Show chart' : 'Show table' }}</button>
    </div>

    <!-- Phones: horizontal bars, one row per endpoint with its numbers (the SVG text would be too small to read). -->
    <ul v-if="!showTable" class="space-y-3 md:hidden">
      <li v-for="s in stats" :key="s.operation">
        <div class="flex items-baseline justify-between gap-2 text-xs">
          <span class="min-w-0 truncate font-mono">{{ s.operation }}</span>
          <span class="shrink-0 tabular-nums text-muted-foreground">p50 <b class="text-foreground">{{ s.p50 }}</b> · p95 <b class="text-foreground">{{ enough(s) ? s.p95 : `n<${minSamples}` }}</b> ms</span>
        </div>
        <div class="relative mt-1 space-y-0.5">
          <div class="h-2 rounded-sm" :style="{ width: `${Math.max(1, (s.p50 / maxV) * 100)}%`, background: 'var(--series-1)' }" />
          <div v-if="enough(s)" class="h-2 rounded-sm" :style="{ width: `${Math.max(1, (s.p95 / maxV) * 100)}%`, background: 'var(--series-2)' }" />
          <div class="absolute -top-0.5 -bottom-0.5 border-l-2 border-dashed border-muted-foreground" :style="{ left: `${(threshold / maxV) * 100}%` }" aria-hidden="true" />
        </div>
      </li>
    </ul>

    <svg v-if="!showTable" :viewBox="`0 0 ${W} ${H}`" class="hidden w-full max-w-[720px] md:block" role="img" :aria-label="`p50 and p95 response time per endpoint, threshold ${threshold} ms`" @mouseleave="hover = null">
      <g v-for="t in ticks" :key="t">
        <line :x1="M.l" :x2="W - M.r" :y1="y(t)" :y2="y(t)" stroke="var(--grid)" stroke-width="1" />
        <text :x="M.l - 8" :y="y(t) + 4" text-anchor="end" font-size="11" fill="var(--muted-foreground)">{{ t }}</text>
      </g>
      <text :x="12" :y="M.t + ih / 2" font-size="11" fill="var(--muted-foreground)" :transform="`rotate(-90 12 ${M.t + ih / 2})`" text-anchor="middle">ms</text>

      <g v-for="(s, i) in stats" :key="s.operation">
        <rect :x="M.l + i * group" :y="M.t" :width="group" :height="ih" fill="transparent" @mousemove="onMove($event, i)" />
        <path v-for="(se, j) in series.filter((x) => x.key === 'p50' || enough(s))" :key="se.key" :d="barPath(M.l + i * group + group / 2 - barW - 1 + j * (barW + 2), s[se.key], barW)" :fill="se.color" pointer-events="none" :opacity="hover && hover.i !== i ? 0.45 : 1" />
        <text :x="M.l + i * group + group / 2" :y="H - M.b + 16" text-anchor="middle" font-size="11" fill="var(--foreground)">{{ s.operation }}</text>
      </g>

      <line :x1="M.l" :x2="W - M.r" :y1="y(threshold)" :y2="y(threshold)" stroke="var(--muted-foreground)" stroke-width="1.5" stroke-dasharray="5 4" />
      <text :x="W - M.r" :y="y(threshold) - 5" text-anchor="end" font-size="11" fill="var(--muted-foreground)">threshold {{ threshold }} ms</text>
    </svg>

    <div v-if="hover && !showTable" class="pointer-events-none absolute z-10 hidden md:block rounded-md border border-border bg-card px-3 py-2 text-xs shadow-md" :style="{ left: `${Math.min(hover.x + 14, 560)}px`, top: `${hover.y + 14}px` }">
      <div class="mb-1 font-medium">{{ stats[hover.i].operation }}</div>
      <div v-for="se in series" :key="se.key" class="flex items-center gap-2"><span class="inline-block size-2 rounded-sm" :style="{ background: se.color }" />{{ se.label }} <b class="ml-auto tabular-nums">{{ se.key === 'p95' && !enough(stats[hover.i]) ? `n<${minSamples}` : `${stats[hover.i][se.key]} ms` }}</b></div>
      <div class="flex gap-2 text-muted-foreground">p99 <span class="ml-auto tabular-nums">{{ enough(stats[hover.i]) ? `${stats[hover.i].p99} ms` : '-' }}</span></div>
      <div class="flex gap-2 text-muted-foreground">samples <span class="ml-auto tabular-nums">{{ stats[hover.i].samples }}</span></div>
      <div v-if="stats[hover.i].serverP50 !== undefined" class="flex gap-2 text-muted-foreground">server p50 <span class="ml-auto tabular-nums">{{ stats[hover.i].serverP50 }} ms</span></div>
      <div class="flex gap-2 text-muted-foreground">available <span class="ml-auto tabular-nums">{{ stats[hover.i].availabilityPct }}%</span></div>
    </div>

    <table v-if="showTable" class="w-full text-sm tabular-nums">
      <thead><tr class="border-b border-border text-left text-xs text-muted-foreground"><th class="py-1.5">Endpoint</th><th class="text-right">p50</th><th class="text-right">p95</th><th class="text-right">p99</th></tr></thead>
      <tbody><tr v-for="s in stats" :key="s.operation" class="border-b border-border last:border-0"><td class="py-1.5">{{ s.operation }}</td><td class="text-right tabular-nums">{{ s.p50 }}</td><td class="text-right tabular-nums">{{ enough(s) ? s.p95 : `n<${minSamples}` }}</td><td class="text-right tabular-nums">{{ enough(s) ? s.p99 : '-' }}</td></tr></tbody>
    </table>
  </div>
</template>
