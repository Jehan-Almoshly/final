import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import { FileText, Download, Calendar, Circle } from "lucide-react";
import { toast } from "sonner";

const ReportsTab = () => {
  const [selectedFormat, setSelectedFormat] = useState<string | null>(null);
  const { data: vulnerabilities = [] } = useQuery({
    queryKey: ["vulnerabilities"],
    queryFn: async () => {
      const { data, error } = await supabase.from("vulnerabilities").select("*");
      if (error) throw error;
      return data;
    },
  });

  const { data: summary = [] } = useQuery({
    queryKey: ["vulnerability_summary"],
    queryFn: async () => {
      const { data, error } = await supabase
        .from("vulnerability_summary")
        .select("*")
        .order("sort_order", { ascending: true });
      if (error) throw error;
      return data;
    },
  });

  // Top 5 vulnerabilities by count
  const top5 = [...vulnerabilities]
    .sort((a, b) => b.vulnerability_count - a.vulnerability_count)
    .slice(0, 5);

  const criticalCount = vulnerabilities.filter((v) => v.exprt_rating === "Critical").length;

  const handleDownload = (format: string) => {
    const headers = ["CVE ID", "Severity", "Rating", "Status", "Exploit", "Count", "Remediations"];
    const rows = vulnerabilities.map((v) => [v.cve_id, v.cvss_severity, v.exprt_rating, v.status, v.exploit_status, v.vulnerability_count, v.remediations]);

    if (format === "CSV") {
      const csv = [headers.join(","), ...rows.map((r) => r.join(","))].join("\n");
      const blob = new Blob([csv], { type: "text/csv" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a"); a.href = url; a.download = "vulnerabilities_report.csv"; a.click();
      URL.revokeObjectURL(url);
      toast.success("CSV report downloaded");
    } else if (format === "PDF") {
      const content = `Vulnerability Report\n\n${headers.join(" | ")}\n${"-".repeat(80)}\n${rows.map((r) => r.join(" | ")).join("\n")}`;
      const blob = new Blob([content], { type: "application/pdf" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a"); a.href = url; a.download = "vulnerabilities_report.pdf"; a.click();
      URL.revokeObjectURL(url);
      toast.success("PDF report downloaded");
    } else if (format === "HTML") {
      const html = `<!DOCTYPE html><html><head><title>Vulnerability Report</title><style>body{font-family:monospace;background:#0f172a;color:#06b6d4;padding:20px}table{border-collapse:collapse;width:100%}th,td{border:1px solid #1e293b;padding:8px;text-align:left}th{background:#1e293b}</style></head><body><h1>Vulnerability Report</h1><table><tr>${headers.map((h) => `<th>${h}</th>`).join("")}</tr>${rows.map((r) => `<tr>${r.map((c) => `<td>${c}</td>`).join("")}</tr>`).join("")}</table></body></html>`;
      const blob = new Blob([html], { type: "text/html" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a"); a.href = url; a.download = "vulnerabilities_report.html"; a.click();
      URL.revokeObjectURL(url);
      toast.success("HTML report downloaded");
    }
  };

  const summaryColors: Record<string, string> = {
    "Total Vulnerabilities": "text-primary",
    Open: "text-primary",
    "In Progress": "text-primary",
    Closed: "text-primary",
    "Actively Exploited": "text-primary",
    "Unique CVE IDs": "text-primary",
  };

  return (
    <div className="space-y-4">
      {/* Reports header */}
      <div className="bg-card rounded-lg border border-border p-5">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <FileText className="w-4 h-4 text-primary" />
            <h3 className="text-sm font-semibold text-foreground">Reports</h3>
          </div>
          <div className="flex items-center gap-2">
            {["CSV", "PDF", "HTML"].map((format) => (
              <button
                key={format}
                onClick={() => {
                  setSelectedFormat(format);
                  handleDownload(format);
                }}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md border text-xs font-medium transition-colors ${
                  selectedFormat === format
                    ? "border-primary text-primary bg-primary/10"
                    : "border-border text-muted-foreground hover:text-foreground hover:border-foreground/30"
                }`}
              >
                <FileText className="w-3 h-3" />
                {format}
              </button>
            ))}
          </div>
        </div>

        {/* Executive summary */}
        <div className="bg-secondary/50 rounded-lg p-4">
          <p className="text-sm text-muted-foreground">
            Last executive summary:{" "}
            <strong className="text-foreground">{criticalCount} critical vulnerabilities</strong>,{" "}
            <strong className="text-foreground">{vulnerabilities.length} vulnerability IDs</strong>,{" "}
            <span className="text-primary cursor-pointer">top remediation items</span>. Full report includes all charts and scan data.
          </p>
          <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground">
            <span className="flex items-center gap-1">
              <Calendar className="w-3 h-3" />
              March 2026
            </span>
            <span className="flex items-center gap-1">
              <Circle className="w-3 h-3" />
              350 assets
            </span>
          </div>
        </div>
      </div>

      {/* Bottom cards */}
      <div className="grid grid-cols-2 gap-4">
        {/* Top 5 vulnerabilities */}
        <div className="bg-card rounded-lg border border-border p-5">
          <h3 className="text-sm font-semibold text-foreground mb-4">Top 5 vulnerabilities</h3>
          <div className="space-y-4">
            {top5.map((v, i) => (
              <div key={v.id} className="flex items-center gap-3">
                <span className="text-primary font-bold text-sm">{i + 1}.</span>
                <span className="text-primary font-mono text-xs">{v.cve_id}</span>
                <span className="text-muted-foreground text-xs">({v.vulnerability_count} assets)</span>
              </div>
            ))}
          </div>
        </div>

        {/* Vulnerability Summary */}
        <div className="bg-card rounded-lg border border-border p-5">
          <h3 className="text-sm font-semibold text-foreground mb-4">Vulnerability Summary</h3>
          <div className="space-y-3">
            {summary.map((s) => (
              <div key={s.id} className="flex items-center justify-between">
                <span className="text-sm text-muted-foreground">{s.label}</span>
                <span className={`text-sm font-bold ${summaryColors[s.label] || "text-foreground"}`}>
                  {s.value}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default ReportsTab;
