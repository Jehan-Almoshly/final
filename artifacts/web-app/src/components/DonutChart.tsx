import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from "recharts";

interface DonutChartProps {
  title: string;
  data: { name: string; value: number; color: string }[];
}

const DonutChart = ({ title, data }: DonutChartProps) => {
  return (
    <div className="bg-card rounded-lg p-5 border border-border">
      <h3 className="text-sm font-semibold text-foreground mb-4">{title}</h3>
      <div className="flex flex-col items-center">
        <ResponsiveContainer width="100%" height={180}>
          <PieChart>
            <Pie
              data={data}
              cx="50%"
              cy="50%"
              innerRadius={55}
              outerRadius={80}
              paddingAngle={2}
              dataKey="value"
              stroke="none"
            >
              {data.map((entry, i) => (
                <Cell key={i} fill={entry.color} />
              ))}
            </Pie>
            <Tooltip
              contentStyle={{
                backgroundColor: "hsl(215 25% 10%)",
                border: "1px solid hsl(215 20% 18%)",
                borderRadius: "8px",
                color: "hsl(210 40% 92%)",
                fontSize: "12px",
              }}
            />
          </PieChart>
        </ResponsiveContainer>
        <div className="flex flex-wrap gap-x-4 gap-y-1 mt-2 justify-center">
          {data.map((d, i) => (
            <div key={i} className="flex items-center gap-1.5 text-xs text-muted-foreground">
              <span
                className="w-2.5 h-2.5 rounded-sm"
                style={{ backgroundColor: d.color }}
              />
              <span>
                {d.name} {d.value >= 1000 ? `${(d.value / 1000).toFixed(1)}k` : d.value}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default DonutChart;
