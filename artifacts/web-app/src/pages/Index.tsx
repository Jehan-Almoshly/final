import { useState } from "react";
import AppSidebar from "@/components/AppSidebar";
import TopBar from "@/components/TopBar";
import FilterBar from "@/components/FilterBar";
import DashboardDonuts from "@/components/DashboardDonuts";
import ScannedAssetsTable from "@/components/ScannedAssetsTable";

const Index = () => {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

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
          <DashboardDonuts />
          <ScannedAssetsTable />
        </main>
      </div>
    </div>
  );
};

export default Index;
