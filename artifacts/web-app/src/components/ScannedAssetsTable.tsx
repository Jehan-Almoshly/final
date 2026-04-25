import { useQuery } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import { Monitor } from "lucide-react";

const riskStyles: Record<string, string> = {
  Critical: "bg-severity-critical/15 text-severity-critical",
  High: "bg-severity-high/15 text-severity-high",
  Medium: "bg-severity-medium/15 text-severity-medium",
  Low: "bg-severity-low/15 text-severity-low",
};

const ScannedAssetsTable = () => {
  const { data: assets = [] } = useQuery({
    queryKey: ["scanned_assets"],
    queryFn: async () => {
      const { data, error } = await supabase.from("scanned_assets").select("*");
      if (error) throw error;
      return data;
    },
  });

  return (
    <div className="bg-card rounded-lg border border-border">
      <div className="flex items-center justify-between px-5 py-4">
        <div className="flex items-center gap-2">
          <Monitor className="w-4 h-4 text-primary" />
          <h3 className="text-sm font-semibold text-foreground">Scanned Assets</h3>
        </div>
        <button className="text-xs text-primary hover:text-primary/80 transition-colors">All assets</button>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-t border-border">
              <th className="text-left px-5 py-3 text-xs font-semibold text-muted-foreground tracking-wider">IP</th>
              <th className="text-left px-5 py-3 text-xs font-semibold text-muted-foreground tracking-wider">HOSTNAME</th>
              <th className="text-left px-5 py-3 text-xs font-semibold text-muted-foreground tracking-wider">OS</th>
              <th className="text-left px-5 py-3 text-xs font-semibold text-muted-foreground tracking-wider">OPEN PORTS</th>
              <th className="text-left px-5 py-3 text-xs font-semibold text-muted-foreground tracking-wider">RISK</th>
              <th className="text-left px-5 py-3 text-xs font-semibold text-muted-foreground tracking-wider">LAST SCAN</th>
            </tr>
          </thead>
          <tbody>
            {assets.map((a) => (
              <tr key={a.id} className="border-t border-border hover:bg-secondary/50 transition-colors">
                <td className="px-5 py-3 text-primary font-mono text-xs">{a.ip_address}</td>
                <td className="px-5 py-3 text-foreground">{a.hostname}</td>
                <td className="px-5 py-3 text-muted-foreground">{a.os}</td>
                <td className="px-5 py-3 text-muted-foreground font-mono text-xs">{a.open_ports}</td>
                <td className="px-5 py-3">
                  <span className={`px-2 py-0.5 rounded text-xs font-medium ${riskStyles[a.risk] || ""}`}>
                    {a.risk}
                  </span>
                </td>
                <td className="px-5 py-3 text-muted-foreground">{a.last_scan}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default ScannedAssetsTable;
