import DonutChart from "@/components/DonutChart";
import { useChartView, type ChartViewName } from "@/hooks/useChartView";

interface DonutDef {
  view: ChartViewName;
  title: string;
  subtitle: string;
  centerLabel: string;
  emptyHint: string;
}

const DONUTS: DonutDef[] = [
  {
    view: "chart_vulns_by_exprt",
    title: "Vulnerabilities by ExPRT rating",
    subtitle: "Severity distribution of matched CVEs",
    centerLabel: "Vulns",
    emptyHint:
      "No CVE matches yet. Run a vulnerability scan to populate severity data from NVD.",
  },
  {
    view: "chart_findings_by_type",
    title: "Vulnerabilities by type",
    subtitle: "Findings grouped by detection category",
    centerLabel: "Findings",
    emptyHint:
      "No findings yet. Once any scan completes, results appear here split by tool category.",
  },
  {
    view: "chart_exploitability_risk",
    title: "Exploitability risk",
    subtitle: "Live correlation against ExploitDB",
    centerLabel: "CVEs",
    emptyHint:
      "Awaiting scan data. Each finding is correlated with ExploitDB to show real-world risk.",
  },
  {
    view: "chart_attack_vector",
    title: "Attack vector",
    subtitle: "How an attacker can reach the vulnerability (CVSS)",
    centerLabel: "CVEs",
    emptyHint:
      "No CVSS vectors yet. Network/Local/Physical reach will populate after the first matched CVE.",
  },
  {
    view: "chart_exploit_types",
    title: "Exploit types",
    subtitle: "Distribution of available public exploits",
    centerLabel: "Exploits",
    emptyHint:
      "No exploits indexed yet. Run scripts/index_exploitdb.py on your Kali agent — the donut populates as soon as the local ExploitDB mirror is loaded.",
  },
  {
    view: "chart_top_vulnerable_products",
    title: "Top vulnerable products",
    subtitle: "Products contributing the most CVEs across your scans",
    centerLabel: "Products",
    emptyHint:
      "No fingerprints yet. Detected vendor/product combinations from scans will rank here.",
  },
];

const DonutCard = ({ def }: { def: DonutDef }) => {
  const { data, isLoading } = useChartView(def.view);
  return (
    <DonutChart
      title={def.title}
      subtitle={def.subtitle}
      centerLabel={def.centerLabel}
      emptyHint={def.emptyHint}
      loading={isLoading}
      data={data?.data ?? []}
    />
  );
};

const DashboardDonuts = () => {
  return (
    <div className="space-y-3">
      <div className="flex items-baseline justify-between">
        <h2 className="text-base font-semibold text-foreground tracking-tight">
          Risk overview
        </h2>
        <span className="text-[11px] text-muted-foreground">
          Computed live from scan_findings · NVD · ExploitDB
        </span>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
        {DONUTS.map((d) => (
          <DonutCard key={d.view} def={d} />
        ))}
      </div>
    </div>
  );
};

export default DashboardDonuts;
