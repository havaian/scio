<script setup lang="ts">
import { cva, type VariantProps } from 'class-variance-authority';
import { cn } from '@/lib/utils';

const button = cva(
  'inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-md text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50',
  {
    variants: {
      variant: {
        default: 'bg-primary text-primary-foreground hover:opacity-90',
        outline: 'border border-border bg-transparent hover:bg-accent',
        ghost: 'hover:bg-accent',
      },
      size: { default: 'h-10 px-4 sm:h-9', sm: 'h-9 px-3 text-xs sm:h-8' },
    },
    defaultVariants: { variant: 'default', size: 'default' },
  },
);
type Props = { variant?: VariantProps<typeof button>['variant']; size?: VariantProps<typeof button>['size']; class?: string; disabled?: boolean };
defineProps<Props>();
</script>
<template>
  <button :disabled="disabled" :class="cn(button({ variant, size }), $props.class)"><slot /></button>
</template>
