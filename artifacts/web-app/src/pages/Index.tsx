import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import AppSidebar from "@/components/AppSidebar";
import TopBar from "@/components/TopBar";
import FilterBar from "@/components/FilterBar";
import SeverityCards from "@/components/SeverityCards";
import DonutChart from "@/components/DonutChart";
import ReviewStatusCard from "@/components/ReviewStatusCard";
import ScannedAssetsTable from "@/components/ScannedAssetsTable";

const Index = () => {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

  const { data: chartData = [] } = useQuery({
    queryKey: ["chart_data"],
    queryFn: async () => {
      const { data, error } = await supabase
        .from("chart_data")
        .select("*")
        .order("sort_order", { ascending: true });
      if (error) throw error;
      return data;
    },
  });

  // Group chart data by chart_key
  const groupedCharts = chartData.reduce((acc, item) => {
    if (!acc[item.chart_key]) {
      acc[item.chart_key] = { title: item.chart_title, data: [] };
    }
    acc[item.chart_key].data.push({
      name: item.segment_name,
      value: item.segment_value,
      color: item.segment_color,
    });
    return acc;
  }, {} as Record<string, { title: string; data: { name: string; value: number; color: string }[] }>);

  return (
    <div className="flex h-screen overflow-hidden">
      <AppSidebar
        collapsed={sidebarCollapsed}
        onToggle={() => setSidebarCollapsed(!sidebarCollapsed)}
        activePage="dashboard"
      />
      <div className="flex-1 flex flex-col overflow-hidden">
        <TopBar />
        <main className="flex-1 overflow-y-auto p-6 space-y-6">
          <FilterBar />
          <SeverityCards />
          <div className="grid grid-cols-2 gap-4">
            {groupedCharts["exprt"] && (
              <DonutChart title={groupedCharts["exprt"].title} data={groupedCharts["exprt"].data} />
            )}
            {groupedCharts["type"] && (
              <DonutChart title={groupedCharts["type"].title} data={groupedCharts["type"].data} />
            )}
          </div>
          <div className="grid grid-cols-2 gap-4">
            {groupedCharts["perimeter"] && (
              <DonutChart title={groupedCharts["perimeter"].title} data={groupedCharts["perimeter"].data} />
            )}
            <ReviewStatusCard />
          </div>
          <ScannedAssetsTable />
        </main>
      </div>
    </div>
  );
};

export default Index;
