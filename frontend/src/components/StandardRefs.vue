<script setup lang="ts">
import { BookOpen } from 'lucide-vue-next';
import type { StandardRef } from '@/lib/api';
import { store } from '@/lib/store';

// Clause chips linking to the source documents (GE-XS2A, BG-IG, ...).
defineProps<{ standard?: StandardRef | null; compact?: boolean }>();
const docOf = (ref: string) => store.report?.standards?.documents?.[ref.split(' ')[0]];
</script>

<template>
  <div v-if="standard" class="flex flex-wrap items-center gap-1 text-[11px]">
    <BookOpen v-if="!compact" class="size-3.5 text-muted-foreground" />
    <template v-for="r in standard.refs" :key="r">
      <a v-if="docOf(r)" :href="docOf(r)!.url" target="_blank" rel="noopener" :title="docOf(r)!.title" class="rounded border border-border px-1.5 py-0.5 font-mono hover:bg-accent" @click.stop>{{ r }}</a>
      <span v-else class="rounded border border-border px-1.5 py-0.5 font-mono">{{ r }}</span>
    </template>
    <span v-if="!standard.refs.length" class="text-muted-foreground">no clause (informational or assumed threshold)</span>
    <span v-if="!standard.verified" class="rounded bg-muted px-1.5 py-0.5 text-muted-foreground" title="Clause not checked against the source text">unverified</span>
    <span v-if="standard.note && !compact" class="w-full text-muted-foreground">{{ standard.note }}</span>
  </div>
  <div v-else class="text-[11px] text-muted-foreground">No clause mapped</div>
</template>
