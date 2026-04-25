import { Bookmark, ChevronDown, Plus, X } from "lucide-react";

const filters = [
  { label: "Saved filters", icon: Bookmark },
  { label: "Asset type" },
  { label: "Subordinates" },
  { label: "Last seen" },
  { label: "Asset confidence", badge: "1 excluded" },
];

const FilterBar = () => {
  return (
    <div className="flex items-center gap-2 flex-wrap">
      {filters.map((f, i) => (
        <button
          key={i}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-full border border-border text-sm text-muted-foreground hover:text-foreground hover:border-foreground/30 transition-colors"
        >
          {f.icon && <f.icon className="w-3.5 h-3.5" />}
          <span>{f.label}</span>
          {f.badge && (
            <span className="ml-1 px-1.5 py-0.5 rounded-full bg-severity-high/20 text-severity-high text-xs">
              {f.badge}
            </span>
          )}
          <ChevronDown className="w-3 h-3 ml-0.5" />
        </button>
      ))}
      <button className="flex items-center gap-1.5 px-3 py-1.5 rounded-full text-sm text-primary hover:text-primary/80 transition-colors">
        <Plus className="w-3.5 h-3.5" />
        Add/remove filters
      </button>
      <button className="text-sm text-muted-foreground hover:text-foreground transition-colors">
        Clear all
      </button>
    </div>
  );
};

export default FilterBar;
