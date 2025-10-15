import { LucideIcon } from 'lucide-react';
import { Card, CardContent } from './ui/card';

interface StatCardProps {
  title: string;
  value: string | number;
  icon?: LucideIcon;
  trend?: {
    value: number;
    isPositive: boolean;
  };
  valueColor?: string;
}

export function StatCard({ title, value, icon: Icon, trend, valueColor }: StatCardProps) {
  return (
    <Card>
      <CardContent className="pt-6">
        <div className="flex items-start justify-between">
          <div className="flex-1">
            <div className={`text-2xl mb-1 ${valueColor || ''}`}>
              {value}
            </div>
            <div className="text-sm text-gray-600">{title}</div>
            {trend && (
              <div className={`text-xs mt-1 ${trend.isPositive ? 'text-green-600' : 'text-red-600'}`}>
                {trend.isPositive ? '↑' : '↓'} {Math.abs(trend.value)}%
              </div>
            )}
          </div>
          {Icon && (
            <div className="w-10 h-10 bg-gray-100 rounded-lg flex items-center justify-center">
              <Icon className="h-5 w-5 text-gray-600" />
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
