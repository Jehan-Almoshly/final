export type Json =
  | string
  | number
  | boolean
  | null
  | { [key: string]: Json | undefined }
  | Json[]

export type Database = {
  // Allows to automatically instantiate createClient with right options
  // instead of createClient<Database, { PostgrestVersion: 'XX' }>(URL, KEY)
  __InternalSupabase: {
    PostgrestVersion: "14.4"
  }
  public: {
    Tables: {
      admin_users: {
        Row: {
          email: string
          id: string
          joined_at: string
          name: string
          role: string
        }
        Insert: {
          email: string
          id?: string
          joined_at?: string
          name: string
          role?: string
        }
        Update: {
          email?: string
          id?: string
          joined_at?: string
          name?: string
          role?: string
        }
        Relationships: []
      }
      chart_data: {
        Row: {
          chart_key: string
          chart_title: string
          id: string
          segment_color: string
          segment_name: string
          segment_value: number
          sort_order: number
        }
        Insert: {
          chart_key: string
          chart_title: string
          id?: string
          segment_color: string
          segment_name: string
          segment_value?: number
          sort_order?: number
        }
        Update: {
          chart_key?: string
          chart_title?: string
          id?: string
          segment_color?: string
          segment_name?: string
          segment_value?: number
          sort_order?: number
        }
        Relationships: []
      }
      notification_settings: {
        Row: {
          description: string
          enabled: boolean
          id: string
          label: string
          setting_key: string
          sort_order: number
        }
        Insert: {
          description: string
          enabled?: boolean
          id?: string
          label: string
          setting_key: string
          sort_order?: number
        }
        Update: {
          description?: string
          enabled?: boolean
          id?: string
          label?: string
          setting_key?: string
          sort_order?: number
        }
        Relationships: []
      }
      profiles: {
        Row: {
          avatar_url: string | null
          created_at: string
          display_name: string | null
          id: string
          updated_at: string
          user_id: string
        }
        Insert: {
          avatar_url?: string | null
          created_at?: string
          display_name?: string | null
          id?: string
          updated_at?: string
          user_id: string
        }
        Update: {
          avatar_url?: string | null
          created_at?: string
          display_name?: string | null
          id?: string
          updated_at?: string
          user_id?: string
        }
        Relationships: []
      }
      remediation_closed: {
        Row: {
          color: string
          id: string
          in_compliance: number
          not_in_compliance: number
          rating: string
          sort_order: number
          time_frame: string
        }
        Insert: {
          color?: string
          id?: string
          in_compliance?: number
          not_in_compliance?: number
          rating: string
          sort_order?: number
          time_frame: string
        }
        Update: {
          color?: string
          id?: string
          in_compliance?: number
          not_in_compliance?: number
          rating?: string
          sort_order?: number
          time_frame?: string
        }
        Relationships: []
      }
      remediation_open: {
        Row: {
          color: string
          id: string
          in_compliance: number
          not_in_compliance: number
          rating: string
          sort_order: number
          time_frame: string
        }
        Insert: {
          color?: string
          id?: string
          in_compliance?: number
          not_in_compliance?: number
          rating: string
          sort_order?: number
          time_frame: string
        }
        Update: {
          color?: string
          id?: string
          in_compliance?: number
          not_in_compliance?: number
          rating?: string
          sort_order?: number
          time_frame?: string
        }
        Relationships: []
      }
      review_status: {
        Row: {
          category: string
          id: string
          not_reviewed: number
          reviewed: number
        }
        Insert: {
          category: string
          id?: string
          not_reviewed?: number
          reviewed?: number
        }
        Update: {
          category?: string
          id?: string
          not_reviewed?: number
          reviewed?: number
        }
        Relationships: []
      }
      scan_results: {
        Row: {
          completed_at: string | null
          created_at: string
          critical_count: number
          description: string | null
          high_count: number
          id: string
          low_count: number
          medium_count: number
          name: string
          options: string | null
          started_at: string
          status: string
          target: string
          tool: string
          total_findings: number
        }
        Insert: {
          completed_at?: string | null
          created_at?: string
          critical_count?: number
          description?: string | null
          high_count?: number
          id?: string
          low_count?: number
          medium_count?: number
          name: string
          options?: string | null
          started_at?: string
          status?: string
          target: string
          tool: string
          total_findings?: number
        }
        Update: {
          completed_at?: string | null
          created_at?: string
          critical_count?: number
          description?: string | null
          high_count?: number
          id?: string
          low_count?: number
          medium_count?: number
          name?: string
          options?: string | null
          started_at?: string
          status?: string
          target?: string
          tool?: string
          total_findings?: number
        }
        Relationships: []
      }
      scanned_assets: {
        Row: {
          created_at: string
          hostname: string
          id: string
          ip_address: string
          last_scan: string
          open_ports: string
          os: string
          risk: string
        }
        Insert: {
          created_at?: string
          hostname: string
          id?: string
          ip_address: string
          last_scan?: string
          open_ports: string
          os: string
          risk?: string
        }
        Update: {
          created_at?: string
          hostname?: string
          id?: string
          ip_address?: string
          last_scan?: string
          open_ports?: string
          os?: string
          risk?: string
        }
        Relationships: []
      }
      severity_stats: {
        Row: {
          id: string
          label: string
          sort_order: number
          value: string
        }
        Insert: {
          id?: string
          label: string
          sort_order?: number
          value: string
        }
        Update: {
          id?: string
          label?: string
          sort_order?: number
          value?: string
        }
        Relationships: []
      }
      system_logs: {
        Row: {
          id: string
          message: string
          sort_order: number
          timestamp: string
        }
        Insert: {
          id?: string
          message: string
          sort_order?: number
          timestamp?: string
        }
        Update: {
          id?: string
          message?: string
          sort_order?: number
          timestamp?: string
        }
        Relationships: []
      }
      user_roles: {
        Row: {
          id: string
          role: Database["public"]["Enums"]["app_role"]
          user_id: string
        }
        Insert: {
          id?: string
          role: Database["public"]["Enums"]["app_role"]
          user_id: string
        }
        Update: {
          id?: string
          role?: Database["public"]["Enums"]["app_role"]
          user_id?: string
        }
        Relationships: []
      }
      vuln_by_exploit: {
        Row: {
          color: string
          id: string
          label: string
          sort_order: number
          value: number
        }
        Insert: {
          color?: string
          id?: string
          label: string
          sort_order?: number
          value?: number
        }
        Update: {
          color?: string
          id?: string
          label?: string
          sort_order?: number
          value?: number
        }
        Relationships: []
      }
      vuln_by_status: {
        Row: {
          color: string
          id: string
          label: string
          sort_order: number
          value: number
        }
        Insert: {
          color?: string
          id?: string
          label: string
          sort_order?: number
          value?: number
        }
        Update: {
          color?: string
          id?: string
          label?: string
          sort_order?: number
          value?: number
        }
        Relationships: []
      }
      vuln_daily_open: {
        Row: {
          count: number
          day: number
          id: string
        }
        Insert: {
          count?: number
          day: number
          id?: string
        }
        Update: {
          count?: number
          day?: number
          id?: string
        }
        Relationships: []
      }
      vuln_rating_overview: {
        Row: {
          color: string
          id: string
          label: string
          percentage: number
          sort_order: number
          value: number
        }
        Insert: {
          color?: string
          id?: string
          label: string
          percentage?: number
          sort_order?: number
          value?: number
        }
        Update: {
          color?: string
          id?: string
          label?: string
          percentage?: number
          sort_order?: number
          value?: number
        }
        Relationships: []
      }
      vuln_risk_score: {
        Row: {
          color: string
          id: string
          label: string
          sort_order: number
          value: number
        }
        Insert: {
          color?: string
          id?: string
          label: string
          sort_order?: number
          value?: number
        }
        Update: {
          color?: string
          id?: string
          label?: string
          sort_order?: number
          value?: number
        }
        Relationships: []
      }
      vuln_status_overview: {
        Row: {
          color: string
          id: string
          label: string
          percentage: number
          sort_order: number
          value: number
        }
        Insert: {
          color?: string
          id?: string
          label: string
          percentage?: number
          sort_order?: number
          value?: number
        }
        Update: {
          color?: string
          id?: string
          label?: string
          percentage?: number
          sort_order?: number
          value?: number
        }
        Relationships: []
      }
      vulnerabilities: {
        Row: {
          created_at: string
          cve_id: string
          cvss_severity: string
          description: string | null
          exploit_status: string
          exprt_rating: string
          id: string
          remediations: number
          status: string
          vulnerability_count: number
        }
        Insert: {
          created_at?: string
          cve_id: string
          cvss_severity?: string
          description?: string | null
          exploit_status?: string
          exprt_rating?: string
          id?: string
          remediations?: number
          status?: string
          vulnerability_count?: number
        }
        Update: {
          created_at?: string
          cve_id?: string
          cvss_severity?: string
          description?: string | null
          exploit_status?: string
          exprt_rating?: string
          id?: string
          remediations?: number
          status?: string
          vulnerability_count?: number
        }
        Relationships: []
      }
      vulnerability_summary: {
        Row: {
          id: string
          label: string
          sort_order: number
          value: number
        }
        Insert: {
          id?: string
          label: string
          sort_order?: number
          value?: number
        }
        Update: {
          id?: string
          label?: string
          sort_order?: number
          value?: number
        }
        Relationships: []
      }
    }
    Views: {
      [_ in never]: never
    }
    Functions: {
      has_role: {
        Args: {
          _role: Database["public"]["Enums"]["app_role"]
          _user_id: string
        }
        Returns: boolean
      }
    }
    Enums: {
      app_role: "admin" | "user"
    }
    CompositeTypes: {
      [_ in never]: never
    }
  }
}

type DatabaseWithoutInternals = Omit<Database, "__InternalSupabase">

type DefaultSchema = DatabaseWithoutInternals[Extract<keyof Database, "public">]

export type Tables<
  DefaultSchemaTableNameOrOptions extends
    | keyof (DefaultSchema["Tables"] & DefaultSchema["Views"])
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
        DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
      DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])[TableName] extends {
      Row: infer R
    }
    ? R
    : never
  : DefaultSchemaTableNameOrOptions extends keyof (DefaultSchema["Tables"] &
        DefaultSchema["Views"])
    ? (DefaultSchema["Tables"] &
        DefaultSchema["Views"])[DefaultSchemaTableNameOrOptions] extends {
        Row: infer R
      }
      ? R
      : never
    : never

export type TablesInsert<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Insert: infer I
    }
    ? I
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Insert: infer I
      }
      ? I
      : never
    : never

export type TablesUpdate<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Update: infer U
    }
    ? U
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Update: infer U
      }
      ? U
      : never
    : never

export type Enums<
  DefaultSchemaEnumNameOrOptions extends
    | keyof DefaultSchema["Enums"]
    | { schema: keyof DatabaseWithoutInternals },
  EnumName extends DefaultSchemaEnumNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"]
    : never = never,
> = DefaultSchemaEnumNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"][EnumName]
  : DefaultSchemaEnumNameOrOptions extends keyof DefaultSchema["Enums"]
    ? DefaultSchema["Enums"][DefaultSchemaEnumNameOrOptions]
    : never

export type CompositeTypes<
  PublicCompositeTypeNameOrOptions extends
    | keyof DefaultSchema["CompositeTypes"]
    | { schema: keyof DatabaseWithoutInternals },
  CompositeTypeName extends PublicCompositeTypeNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"]
    : never = never,
> = PublicCompositeTypeNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"][CompositeTypeName]
  : PublicCompositeTypeNameOrOptions extends keyof DefaultSchema["CompositeTypes"]
    ? DefaultSchema["CompositeTypes"][PublicCompositeTypeNameOrOptions]
    : never

export const Constants = {
  public: {
    Enums: {
      app_role: ["admin", "user"],
    },
  },
} as const
