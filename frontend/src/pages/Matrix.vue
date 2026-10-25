<script setup lang="ts">
import { computed } from 'vue';
import Card from '@/components/ui/Card.vue';
import CardHeader from '@/components/ui/CardHeader.vue';
import CardContent from '@/components/ui/CardContent.vue';
import StatusBadge from '@/components/ui/StatusBadge.vue';
import { setBank, store } from '@/lib/store';
import { LAYER_LABEL } from '@/lib/utils';
import RootCauses from '@/components/RootCauses.vue';
import StandardRefs from '@/components/StandardRefs.vue';

const r = computed(() => store.report!);

// Phones: one bank at a time instead of a 13-column table; the cell message is shown inline (no hover on touch).
// Bound to the shared bank filter; with "All banks" the phone view starts at the first target.
const target = computed({ get: () => (store.bank === 'all' ? r.value.targets[0]?.id ?? '' : store.bank), set: (v: string) => setBank(v) });
// Desktop: with a bank chosen, only its column and the checks that apply to it.
const cols = computed(() => r.value.targets.filter((t) => store.bank === 'all' || t.id === store.bank));
const matrixRows = computed(() => (store.bank === 'all' ? r.value.matrix : r.value.matrix.filter((m) => m.cells[store.bank])));
const statusRank: Record<string, number> = { fail: 0, warn: 1, info: 2, skip: 3, pass: 4 };
const rows = computed(() =>
  r.value.matrix
    .filter((m) => m.cells[target.value])
    .sort((a, b) => statusRank[a.cells[target.value]!.status] - statusRank[b.cells[target.value]!.status]),
);
const counts = computed(() => {
  const c: Record<string, number> = { fail: 0, warn: 0, pass: 0 };
  for (const m of rows.value) c[m.cells[target.value]!.status] = (c[m.cells[target.value]!.status] ?? 0) + 1;
  return c;
});
</script>

<template>
  <div class="space-y-6">
  <RootCauses :r="r" />
  <Card>
    <CardHeader title="Incompatibility report" description="Each row is one check; each column a bank or environment. Empty cell: check not applicable to that target (for example, a journey step it was not reached at)." />

    <!-- Phones: pick a bank, see its checks worst first. -->
    <CardContent class="space-y-3 md:hidden">
      <select v-model="target" class="h-10 w-full rounded-md border border-border bg-background px-2 text-sm" aria-label="Bank or environment">
        <option v-for="t in r.targets" :key="t.id" :value="t.id">{{ t.name }}</option>
      </select>
      <div class="text-xs text-muted-foreground">{{ rows.length }} checks · {{ counts.fail }} fail · {{ counts.warn }} warn · {{ counts.pass }} pass</div>
      <ul class="divide-y divide-border">
        <li v-for="m in rows" :key="m.checkId" class="py-3">
          <div class="flex items-start justify-between gap-3">
            <div class="min-w-0">
              <div class="text-sm font-medium leading-snug">{{ m.title }}</div>
              <div class="font-mono text-[11px] text-muted-foreground [overflow-wrap:anywhere]">{{ m.checkId }} · {{ LAYER_LABEL[m.layer] }}</div>
            </div>
            <StatusBadge class="shrink-0" :status="m.cells[target]!.status" :severity="m.cells[target]!.severity" />
          </div>
          <p v-if="m.cells[target]!.message" class="mt-1.5 text-xs leading-relaxed text-muted-foreground [overflow-wrap:anywhere]">{{ m.cells[target]!.message }}</p>
          <StandardRefs class="mt-1.5" :standard="m.standard" compact />
        </li>
      </ul>
      <p v-if="!rows.length" class="py-6 text-center text-sm text-muted-foreground">No checks recorded for this target.</p>
    </CardContent>

    <!-- md and up: full matrix; the check column stays visible while the bank columns scroll sideways. -->
    <CardContent class="hidden px-0 sm:px-0 md:block">
      <!-- Own scroll box (both axes) so the header row and the check column stay put. -->
      <div class="max-h-[calc(100vh-var(--header-h,57px)-6rem)] overflow-auto">
        <table class="w-full border-separate border-spacing-0 text-sm">
          <thead>
            <tr class="text-left text-xs text-muted-foreground">
              <th class="sticky top-0 left-0 z-30 min-w-56 border-b border-r border-border bg-card py-2 pr-3 pl-5 font-medium">Check</th>
              <th class="sticky top-0 z-20 hidden border-b border-border bg-card px-3 py-2 font-medium lg:table-cell">Layer</th>
              <th v-for="t in cols" :key="t.id" class="sticky top-0 z-20 min-w-24 border-b border-border bg-card px-2 py-2 text-center align-bottom font-medium leading-tight">{{ t.name }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="m in matrixRows" :key="m.checkId" class="group">
              <td class="sticky left-0 z-10 min-w-56 border-b border-r border-border bg-card py-2 pr-3 pl-5 group-hover:bg-muted">
                <div>{{ m.title }}</div>
                <div class="font-mono text-[11px] text-muted-foreground">{{ m.checkId }}</div>
                <StandardRefs class="mt-1" :standard="m.standard" compact />
              </td>
              <td class="hidden border-b border-border px-3 py-2 text-xs text-muted-foreground group-hover:bg-muted/50 lg:table-cell">{{ LAYER_LABEL[m.layer] }}</td>
              <td v-for="t in cols" :key="t.id" class="border-b border-border px-2 py-2 text-center group-hover:bg-muted/50" :title="m.cells[t.id]?.message">
                <StatusBadge v-if="m.cells[t.id]" :status="m.cells[t.id]!.status" :severity="m.cells[t.id]!.severity" />
                <span v-else class="text-muted-foreground">·</span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </CardContent>
  </Card>
  </div>
</template>
