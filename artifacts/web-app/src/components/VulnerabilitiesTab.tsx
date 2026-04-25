import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { supabase } from "@/integrations/supabase/client";
import { AlertTriangle, MoreHorizontal } from "lucide-react";
import { cn } from "@/lib/utils";

const filterTags = [
  "Open vulnerabilities",
  "Adversaries",
  "Asset confidence",
  "Asset criticality",
  "Asset roles",
  "CISA KEV",
  "CISA KEV due date compliant",
  "Cloud provider",
  "CVSS complexity",
];

const exploitStyles: Record<string, string> = {
  "Actively used": "bg-severity-critical/15 text-severity-critical",
  "Available": "bg-severity-high/15 text-severity-high",
};

const severityStyles: Record<string, string> = {
  Critical: "text-severity-critical",
  High: "text-severity-high",
  Medium: "text-severity-medium",
  Low: "text-severity-low",
};

const VulnerabilitiesTab = () => {
  const navigate = useNavigate();
  const [filterRating, setFilterRating] = useState("all");
  const [filterExploit, setFilterExploit] = useState("all");
  const [filterStatus, setFilterStatus] = useState("all");
  const [showRatingDrop, setShowRatingDrop] = useState(false);
  const [showExploitDrop, setShowExploitDrop] = useState(false);
  const [showStatusDrop, setShowStatusDrop] = useState(false);

  const { data: vulnerabilities = [] } = useQuery({
    queryKey: ["vulnerabilities"],
    queryFn: async () => {
      const { data, error } = await supabase
        .from("vulnerabilities")
        .select("*")
        .order("created_at", { ascending: true });
      if (error) throw error;
      return data;
    },
  });

  const filtered = vulnerabilities.filter((v) => {
    if (filterRating !== "all" && v.cvss_severity !== filterRating) return false;
    if (filterExploit !== "all" && v.exploit_status !== filterExploit) return false;
    if (filterStatus !== "all" && v.status !== filterStatus) return false;
    return true;
  });

  const ratingOptions = ["All Ratings", "Critical", "High", "Medium", "Low"];
  const exploitOptions = ["All Exploits", "Actively Used", "Available", "Unproven", "None"];
  const statusOptions = ["All Status", "Open", "In Progress", "Closed", "Suppressed"];

  const closeAllDrops = () => { setShowRatingDrop(false); setShowExploitDrop(false); setShowStatusDrop(false); };

  const DropdownFilter = ({
    label, value, options, show, setShow, setValue
  }: {
    label: string; value: string; options: string[]; show: boolean;
    setShow: (v: boolean) => void; setValue: (v: string) => void;
  }) => {
    const allLabel = options[0];
    return (
      <div className="relative">
        <button
          onClick={() => { closeAllDrops(); setShow(!show); }}
          className="flex items-center gap-2 px-3 py-1.5 text-sm bg-secondary border border-border rounded-lg"
        >
          {value === "all" ? allLabel : value}
          <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" /></svg>
        </button>
        {show && (
          <div className="absolute z-10 mt-1 bg-card border border-border rounded-lg shadow-lg py-1 min-w-[160px]">
            {options.map((opt) => {
              const val = opt === allLabel ? "all" : opt;
              const active = value === val;
              return (
                <button
                  key={opt}
                  onClick={() => { setValue(val); setShow(false); }}
                  className={cn("w-full text-left px-3 py-1.5 text-sm hover:bg-accent", active ? "bg-primary text-primary-foreground" : "")}
                >
                  {opt} {active && "✓"}
                </button>
              );
            })}
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="space-y-4">
      {/* Filter row */}
      <div className="flex items-center gap-4">
        <span className="text-sm text-muted-foreground">Filter by:</span>
        <DropdownFilter label="Ratings" value={filterRating} options={ratingOptions} show={showRatingDrop} setShow={setShowRatingDrop} setValue={setFilterRating} />
        <DropdownFilter label="Exploits" value={filterExploit} options={exploitOptions} show={showExploitDrop} setShow={setShowExploitDrop} setValue={setFilterExploit} />
        <DropdownFilter label="Status" value={filterStatus} options={statusOptions} show={showStatusDrop} setShow={setShowStatusDrop} setValue={setFilterStatus} />
        <span className="ml-auto text-sm text-muted-foreground">{filtered.length} results</span>
      </div>

      {/* Info banner */}
      <div className="bg-card rounded-lg border border-border p-4">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-severity-high" />
            <span className="text-sm font-medium text-foreground">
              {filtered.length} vulnerabilities found on {filtered.length} vulnerability IDs
            </span>
          </div>
          <div className="flex items-center gap-4 text-xs text-muted-foreground">
            <span className="flex items-center gap-1">⊕ Grouped by Vulnerability ID</span>
            <span>Create scheduled report</span>
            <span>↓ Export</span>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2 mb-2">
          {filterTags.map((tag, i) => (
            <span key={i} className="text-xs px-2 py-1 rounded text-muted-foreground">
              {tag}
              {i === 2 && (
                <span className="ml-1 px-1.5 py-0.5 rounded-full bg-severity-high/20 text-severity-high text-xs">1 excluded</span>
              )}
            </span>
          ))}
          <span className="text-xs text-primary cursor-pointer">Add/remove filters</span>
        </div>
        <div className="text-right">
          <span className="text-xs text-muted-foreground cursor-pointer hover:text-foreground">Clear all</span>
        </div>
      </div>

      {/* Table */}
      <div className="bg-card rounded-lg border border-border overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border">
              <th className="text-left px-5 py-3 text-xs font-semibold text-muted-foreground tracking-wider">CRITICAL</th>
              <th className="text-left px-5 py-3 text-xs font-semibold text-muted-foreground tracking-wider">EXPRT RATING</th>
              <th className="text-left px-5 py-3 text-xs font-semibold text-muted-foreground tracking-wider">CVSS SEVERITY</th>
              <th className="text-left px-5 py-3 text-xs font-semibold text-muted-foreground tracking-wider">DESCRIPTION</th>
              <th className="text-left px-5 py-3 text-xs font-semibold text-muted-foreground tracking-wider">VULNERABILITIES</th>
              <th className="text-left px-5 py-3 text-xs font-semibold text-muted-foreground tracking-wider">EXPLOIT STATUS</th>
              <th className="text-left px-5 py-3 text-xs font-semibold text-muted-foreground tracking-wider">REMEDIATIONS</th>
              <th className="text-left px-5 py-3 text-xs font-semibold text-muted-foreground tracking-wider">ACTIONS</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((v) => (
              <tr key={v.id} className="border-t border-border hover:bg-secondary/50 transition-colors cursor-pointer" onClick={() => navigate("/scan-results")}>
                <td className="px-5 py-3">
                  <div className="flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-severity-critical" />
                    <span className="text-primary font-mono text-xs">{v.cve_id}</span>
                  </div>
                </td>
                <td className={`px-5 py-3 ${severityStyles[v.exprt_rating] || "text-foreground"}`}>{v.exprt_rating}</td>
                <td className={`px-5 py-3 ${severityStyles[v.cvss_severity] || "text-foreground"}`}>{v.cvss_severity}</td>
                <td className="px-5 py-3 text-muted-foreground max-w-[250px] truncate">{v.description}</td>
                <td className="px-5 py-3 text-foreground text-center">{v.vulnerability_count}</td>
                <td className="px-5 py-3">
                  <span className={`px-2 py-0.5 rounded text-xs font-medium ${exploitStyles[v.exploit_status] || "bg-secondary text-foreground"}`}>
                    ● {v.exploit_status}
                  </span>
                </td>
                <td className="px-5 py-3 text-primary text-center">{v.remediations}</td>
                <td className="px-5 py-3">
                  <button className="text-muted-foreground hover:text-foreground" onClick={(e) => { e.stopPropagation(); navigate("/scan-results"); }}><MoreHorizontal className="w-4 h-4" /></button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default VulnerabilitiesTab;
