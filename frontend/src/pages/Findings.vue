<script setup lang="ts">
import { computed, ref } from 'vue';
import FindingCard from '@/components/FindingCard.vue';
import { setBank, store } from '@/lib/store';
import { LAYERS, LAYER_LABEL } from '@/lib/utils';

const r = computed(() => store.report!);
const names = computed(() => Object.fromEntries(r.value.targets.map((t) => [t.id, t.name])));
// Bank: the shared filter from the page header (same value on every page).
const target = computed({ get: () => store.bank, set: (v: string) => setBank(v) });
const layer = ref('all');
const status = ref('problems');
const q = ref('');

const sevRank: Record<string, number> = { high: 0, medium: 1, low: 2, none: 3 };
const statusRank: Record<string, number> = { fail: 0, warn: 1, info: 2, skip: 3, pass: 4 };
const list = computed(() =>
  r.value.findings
    .filter((f) => target.value === 'all' || f.targetId === target.value)
    .filter((f) => layer.value === 'all' || f.layer === layer.value)
    .filter((f) => (status.value === 'problems' ? ['fail', 'warn'].includes(f.status) : status.value === 'all' || f.status === status.value))
    .filter((f) => !q.value || `${f.title} ${f.message} ${f.endpoint ?? ''} ${f.checkId}`.toLowerCase().includes(q.value.toLowerCase()))
    .sort((a, b) => statusRank[a.status] - statusRank[b.status] || sevRank[a.severity] - sevRank[b.severity]),
);
const sel = 'h-10 min-w-0 rounded-md border border-border bg-background px-2 text-sm sm:h-8';
</script>

<template>
  <div class="space-y-4">
    <div class="grid grid-cols-2 items-center gap-2 sm:flex sm:flex-wrap">
      <!-- Bank: chosen with the bank picker above the page (shared by all pages). -->
      <select v-model="layer" :class="sel" aria-label="Layer">
        <option value="all">All layers</option>
        <option v-for="l in LAYERS" :key="l" :value="l">{{ LAYER_LABEL[l] }}</option>
      </select>
      <select v-model="status" :class="sel" aria-label="Status">
        <option value="problems">Failures and warnings</option>
        <option value="all">All results</option>
        <option value="pass">Passed</option>
        <option value="info">Info</option>
        <option value="skip">Skipped</option>
      </select>
      <input v-model="q" placeholder="Search…" :class="[sel, 'col-span-2 w-full sm:w-56']" />
      <span class="col-span-2 text-right text-xs text-muted-foreground sm:ml-auto">{{ list.length }} results</span>
    </div>
    <div class="grid gap-2">
      <FindingCard v-for="(f, i) in list" :key="`${f.targetId}-${f.checkId}-${i}`" :f="f" :target-name="names[f.targetId]" />
      <p v-if="!list.length" class="py-8 text-center text-sm text-muted-foreground">Nothing matches these filters.</p>
    </div>
  </div>
</template>
