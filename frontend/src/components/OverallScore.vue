<script setup lang="ts">
import Score from '@/components/ui/Score.vue';

// Overall score with the number of checks behind it, so a score from 4 checks never looks like one from 50.
// Below the minimum no score is shown, only the count.
defineProps<{ evaluated: number; overall: number | null; min: number; large?: boolean; noLabel?: boolean }>();
</script>

<template>
  <div class="text-right" :title="evaluated < min ? `Fewer than ${min} evaluated checks: not scored` : `Score from ${evaluated} evaluated checks (pass, fail, warn)`">
    <div v-if="!noLabel" class="text-[10px] text-muted-foreground">Overall</div>
    <Score v-if="evaluated >= min" :value="overall" :large="large" />
    <span v-else class="font-semibold text-muted-foreground" :class="large && 'text-3xl'">-</span>
    <div class="whitespace-nowrap text-[10px] tabular-nums text-muted-foreground">{{ evaluated }} check{{ evaluated === 1 ? '' : 's' }}</div>
  </div>
</template>
