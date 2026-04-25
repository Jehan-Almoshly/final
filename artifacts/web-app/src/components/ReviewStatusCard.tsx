import { useQuery } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";

const ReviewStatusCard = () => {
  const { data: reviewData = [] } = useQuery({
    queryKey: ["review_status"],
    queryFn: async () => {
      const { data, error } = await supabase.from("review_status").select("*");
      if (error) throw error;
      return data;
    },
  });

  const ip = reviewData.find((r) => r.category === "ip");
  const root = reviewData.find((r) => r.category === "root");

  const ipTotal = ip ? ip.reviewed + ip.not_reviewed : 1;
  const ipPercent = ip ? (ip.not_reviewed / ipTotal) * 100 : 0;

  return (
    <div className="bg-card rounded-lg p-5 border border-border">
      <h3 className="text-sm font-semibold text-foreground mb-4">
        Review status · IP / Root domains
      </h3>
      <div className="space-y-4">
        <div className="grid grid-cols-2 gap-3 text-xs">
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-severity-low" />
            <span className="text-muted-foreground">IP reviewed: <strong className="text-foreground">{ip?.reviewed ?? 0}</strong></span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-severity-medium" />
            <span className="text-muted-foreground">IP not reviewed: <strong className="text-foreground">{ip?.not_reviewed?.toLocaleString() ?? 0}</strong></span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-severity-high" />
            <span className="text-muted-foreground">Root reviewed: <strong className="text-foreground">{root?.reviewed ?? 0}</strong></span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-severity-critical" />
            <span className="text-muted-foreground">Root not reviewed: <strong className="text-foreground">{root?.not_reviewed ?? 0}</strong></span>
          </div>
        </div>
        <div className="space-y-3">
          <div className="w-full h-2 bg-secondary rounded-full overflow-hidden">
            <div
              className="h-full rounded-full"
              style={{
                width: `${ipPercent}%`,
                background: "linear-gradient(90deg, hsl(50 95% 55%), hsl(45 95% 55%))",
              }}
            />
          </div>
          <div className="w-full h-2 bg-secondary rounded-full overflow-hidden">
            <div className="h-full rounded-full bg-severity-critical" style={{ width: "0.5%" }} />
          </div>
        </div>
      </div>
    </div>
  );
};

export default ReviewStatusCard;
