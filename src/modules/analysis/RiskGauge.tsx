import React from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, Label } from 'recharts';

interface RiskGaugeProps {
  score: number;
}

const RiskGauge: React.FC<RiskGaugeProps> = ({ score }) => {
  const safeScore = Number.isFinite(Number(score)) ? Math.max(0, Math.min(100, Math.round(Number(score)))) : 0;

  const data = [
    { name: 'Risk', value: safeScore },
    { name: 'Safe', value: 100 - safeScore },
  ];

  const getColor = (s: number) => {
    if (s < 30) return '#10b981'; // Green
    if (s < 60) return '#f59e0b'; // Yellow
    if (s < 85) return '#f97316'; // Orange
    return '#ef4444'; // Red
  };

  const color = getColor(safeScore);

  return (
    <div className="h-48 w-full relative flex flex-col items-center justify-center">
      {/* Glow effect */}
      <div className="absolute inset-0 opacity-20 blur-xl" style={{ background: `radial-gradient(circle, ${color} 0%, transparent 70%)` }}></div>
      
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={data}
            cx="50%"
            cy="50%"
            innerRadius={60}
            outerRadius={80}
            startAngle={180}
            endAngle={0}
            paddingAngle={0}
            dataKey="value"
            stroke="none"
          >
            <Cell key="risk" fill={color} />
            <Cell key="safe" fill="#1f2937" />
            <Label
              value={`${safeScore}/100`}
              position="center"
              fill="#e2e8f0"
              style={{ fontSize: '28px', fontWeight: 'bold', fontFamily: 'JetBrains Mono' }}
            />
          </Pie>
        </PieChart>
      </ResponsiveContainer>
      <div className="absolute bottom-4 text-slate-400 text-xs font-bold uppercase tracking-widest">Risk Score</div>
    </div>
  );
};

export default RiskGauge;