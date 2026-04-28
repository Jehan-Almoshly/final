import { useQuery } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import { Monitor } from "lucide-react";

const riskStyles: Record<string, string> = {
  Critical: "bg-severity-critical/15 text-severity-critical",
  High: "bg-severity-high/15 text-severity-high",
  Medium: "bg-severity-medium/15 text-severity-medium",
  Low: "bg-severity-low/15 text-severity-low",
  Info: "bg-muted/30 text-muted-foreground",
};

const formatDate = (raw: unknown): string => {
  if (!raw) return "—";
  const d = new Date(String(raw));
  if (Number.isNaN(d.getTime())) return String(raw);
  return d.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
};

const ScannedAssetsTable = () => {
  const { data: assets = [], isLoading } = useQuery({
    queryKey: ["scanned_assets"],
    queryFn: async () => {
      const { data, error } = await supabase.from("scanned_assets").select("*");
      if (error) throw error;
      return data ?? [];
    },
  });

  return (
    <div className="bg-card rounded-xl border border-border/80 overflow-hidden">
      <div className="flex items-center justify-between px-5 py-4 border-b border-border/60">
        <div className="flex items-center gap-2">
          <Monitor className="w-4 h-4 text-primary" />
          <h3 className="text-[15px] font-semibold text-foreground tracking-tight">
            Scanned Assets
          </h3>
          {!isLoading && (
            <span className="text-[11px] text-muted-foreground ml-1">
              ({assets.length})
            </span>
          )}
        </div>
        <button className="text-xs text-primary hover:text-primary/80 transition-colors font-medium">
          All assets
        </button>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="bg-secondary/30">
              <th className="text-left px-5 py-3 text-[12px] font-semibold text-primary uppercase tracking-wider">
                IP
              </th>
              <th className="text-left px-5 py-3 text-[12px] font-semibold text-primary uppercase tracking-wider">
                Hostname
              </th>
              <th className="text-left px-5 py-3 text-[12px] font-semibold text-primary uppercase tracking-wider">
                OS
              </th>
              <th className="text-left px-5 py-3 text-[12px] font-semibold text-primary uppercase tracking-wider">
                Open Ports
              </th>
              <th className="text-left px-5 py-3 text-[12px] font-semibold text-primary uppercase tracking-wider">
                Risk
              </th>
              <th className="text-left px-5 py-3 text-[12px] font-semibold text-primary uppercase tracking-wider">
                Last Scan
              </th>
            </tr>
          </thead>
          <tbody>
            {isLoading && (
              <tr>
                <td
                  colSpan={6}
                  className="px-5 py-8 text-center text-sm text-muted-foreground"
                >
                  Loading assets…
                </td>
              </tr>
            )}
            {!isLoading && assets.length === 0 && (
              <tr>
                <td
                  colSpan={6}
                  className="px-5 py-8 text-center text-sm text-muted-foreground"
                >
                  No scanned assets yet — run your first scan from the
                  Vulnerabilities tab.
                </td>
              </tr>
            )}
            {assets.map((a) => (
              <tr
                key={a.id}
                className="border-t border-border/50 hover:bg-secondary/40 transition-colors"
              >
                <td className="px-5 py-3.5 text-primary font-mono text-[13.5px] font-medium">
                  {a.ip_address ?? "—"}
                </td>
                <td className="px-5 py-3.5 text-foreground text-[14px]">
                  {a.hostname ?? "—"}
                </td>
                <td className="px-5 py-3.5 text-foreground/80 text-[14px]">
                  {a.os ?? "—"}
                </td>
                <td className="px-5 py-3.5 text-foreground/80 font-mono text-[13.5px]">
                  {a.open_ports ?? "—"}
                </td>
                <td className="px-5 py-3.5">
                  <span
                    className={`px-2.5 py-1 rounded-md text-[12.5px] font-semibold ${
                      riskStyles[a.risk] ?? "bg-muted/30 text-muted-foreground"
                    }`}
                  >
                    {a.risk ?? "—"}
                  </span>
                </td>
                <td className="px-5 py-3.5 text-foreground/70 text-[13.5px] tabular-nums">
                  {formatDate(a.last_scan)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default ScannedAssetsTable;
