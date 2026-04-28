import { useQuery } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import type { DonutSegment } from "@/components/DonutChart";

export type ChartViewName =
  | "chart_vulns_by_exprt"
  | "chart_findings_by_type"
  | "chart_exploitability_risk"
  | "chart_attack_vector"
  | "chart_exploit_types"
  | "chart_top_vulnerable_products";

interface ChartRow {
  segment_name: string;
  segment_value: number;
  segment_color: string;
  sort_order: number;
}

export function useChartView(view: ChartViewName) {
  return useQuery<{ data: DonutSegment[]; loading: boolean }>({
    queryKey: ["chart_view", view],
    queryFn: async () => {
      // Cast through `any` because the generated Database type only
      // contains the base tables, not these aggregation views.
      const { data, error } = await (supabase as any)
        .from(view)
        .select("*")
        .order("sort_order", { ascending: true });

      if (error) {
        // Missing view (migration not yet applied) → return empty
        // gracefully instead of breaking the whole dashboard.
        if (
          error.code === "42P01" /* undefined_table */ ||
          /relation .* does not exist/i.test(error.message ?? "")
        ) {
          return { data: [], loading: false };
        }
        throw error;
      }

      const rows = (data ?? []) as ChartRow[];
      return {
        data: rows.map((r) => ({
          name: r.segment_name,
          value: Number(r.segment_value) || 0,
          color: r.segment_color,
        })),
        loading: false,
      };
    },
  });
}
