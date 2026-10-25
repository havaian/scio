<script setup lang="ts">
import { Sparkles } from 'lucide-vue-next';
import Card from '@/components/ui/Card.vue';
import CardContent from '@/components/ui/CardContent.vue';
import type { Report } from '@/lib/api';

defineProps<{ ai: Report['ai'] }>();
</script>

<template>
  <Card>
    <CardContent class="flex flex-wrap items-center gap-x-8 gap-y-4 p-4 sm:p-5">
      <div class="flex max-w-md gap-2">
        <Sparkles class="mt-0.5 size-4 shrink-0" />
        <div>
          <div class="text-sm font-semibold">AI triage <span class="font-normal text-muted-foreground">· {{ ai.enabled ? ai.models.join(', ') || 'Jev' : 'off' }}</span></div>
          <p class="mt-1 text-xs leading-relaxed text-muted-foreground">
            Rule-based checks decide pass/fail and the score. Jev (TypeSafe) adds typed, confidence-scored triage: impact and owner per finding.
            Low-confidence answers go to a human; disagreements with the rules are shown, never silently resolved.
            Without a Jev key, a local QVAC model answers the same questions; it has no calibrated confidence, so all its answers go to review.
          </p>
          <p v-if="!ai.enabled && ai.note" class="mt-1 text-xs">{{ ai.note }}</p>
        </div>
      </div>
      <!-- Number above its label; 3 columns on phones, one row from sm. -->
      <dl v-if="ai.enabled" class="grid w-full flex-1 grid-cols-3 gap-x-3 gap-y-4 sm:grid-cols-5 sm:gap-6">
        <div v-for="x in [
          { k: 'Triaged', v: ai.triaged },
          { k: 'Confident', v: ai.auto },
          { k: 'Needs review', v: ai.review },
          { k: 'Human decision', v: ai.human },
          { k: 'Disagree with rules', v: ai.disagreements },
        ]" :key="x.k" class="flex min-w-0 flex-col-reverse items-center justify-center gap-0.5 text-center">
          <dt class="text-[11px] leading-tight text-muted-foreground">{{ x.k }}</dt>
          <dd class="text-xl font-semibold tabular-nums">{{ x.v }}</dd>
        </div>
      </dl>
    </CardContent>
  </Card>
</template>
