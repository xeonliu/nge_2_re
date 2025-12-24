import React, { useState, useMemo } from "react";
import "./MultiTable.css";

// 颜色逻辑
const getProgressColor = (percentage) => {
  if (percentage < 33) return "#c7162b";
  if (percentage < 66) return "#ed6c02";
  return "#0e8a16";
};

// 递归计算某个节点及其所有子节点的汇总数据
const calculateStats = (item) => {
  if (item.isLeaf) {
    return {
      total: item.total || 0,
      translated: item.translated || 0,
      disputed: item.disputed || 0,
      checked: item.checked || 0,
      reviewed: item.reviewed || 0,
    };
  }

  const stats = { total: 0, translated: 0, disputed: 0, checked: 0, reviewed: 0 };
  if (item.content && item.content.length > 0) {
    item.content.forEach((child) => {
      const childStats = calculateStats(child);
      stats.total += childStats.total;
      stats.translated += childStats.translated;
      stats.disputed += childStats.disputed;
      stats.checked += childStats.checked;
      stats.reviewed += childStats.reviewed;
    });
  }
  return stats;
};

const TableRow = ({ item, depth = 0 }) => {
  const [isExpanded, setIsExpanded] = useState(false);
  const toggleExpand = () => setIsExpanded(!isExpanded);

  // 无论是否是叶子节点，都计算（或直接获取）统计数据
  const stats = useMemo(() => calculateStats(item), [item]);
  const percentage = stats.total > 0 ? Math.round((stats.checked / stats.total) * 100) : 0;
  const hasChildren = !item.isLeaf && item.content && item.content.length > 0;

  return (
    <>
      <tr 
        className={hasChildren ? "is-clickable" : ""} 
        onClick={hasChildren ? toggleExpand : undefined}
        style={{ 
          cursor: hasChildren ? 'pointer' : 'default',
          backgroundColor: !item.isLeaf ? `rgba(0,0,0, ${0.02 * (depth + 1)})` : 'transparent' // 给父行加一点背景深浅区分
        }}
      >
        <td style={{ paddingLeft: `${depth * 1.5 + 0.5}rem` }}>
          <div className="u-flex-center">
            {hasChildren ? (
              <button 
                className="u-no-border u-cursor-pointer"
                onClick={(e) => { e.stopPropagation(); toggleExpand(); }}
                style={{ background: 'transparent', width: '1rem', display: 'flex', alignItems: 'center' }}
              >
                <i className={isExpanded ? "p-icon--chevron-down" : "p-icon--chevron-right"}></i>
              </button>
            ) : (
              <span style={{ width: "1rem", display: "inline-block" }}></span>
            )}
            <span style={{ fontWeight: !item.isLeaf ? "600" : "400", marginLeft: "4px" }}>
              {item.name}
            </span>
          </div>
        </td>
        <td>
          <div>
            <div style={{ fontSize: "0.85em", marginBottom: "2px" }}>
              {percentage}% {!item.isLeaf && <span style={{opacity: 0.6, fontSize: '0.9em'}}></span>}
            </div>
            <div className="u-progress-bar" style={{ height: !item.isLeaf ? '6px' : '4px' }}>
              <div 
                className="u-progress-bar__fill" 
                style={{ 
                  width: `${percentage}%`, 
                  backgroundColor: getProgressColor(percentage) 
                }}
              ></div>
            </div>
          </div>
        </td>
        <td className="u-align--right" style={{ fontWeight: !item.isLeaf ? "600" : "400" }}>{stats.total}</td>
        <td className="u-align--right">{stats.translated}</td>
        <td className="u-align--right">{stats.disputed}</td>
        <td className="u-align--right">{stats.checked}</td>
        <td className="u-align--right">{stats.reviewed}</td>
      </tr>
      {isExpanded && hasChildren && item.content.map((child, index) => (
        <TableRow key={index} item={child} depth={depth + 1} />
      ))}
    </>
  );
};

const MultiTable = ({ data }) => {
  // 计算全表总和
  const globalTotals = useMemo(() => {
    return data.reduce((acc, curr) => {
      const stats = calculateStats(curr);
      return {
        total: acc.total + stats.total,
        translated: acc.translated + stats.translated,
        disputed: acc.disputed + stats.disputed,
        checked: acc.checked + stats.checked,
        reviewed: acc.reviewed + stats.reviewed,
      };
    }, { total: 0, translated: 0, disputed: 0, checked: 0, reviewed: 0 });
  }, [data]);

  const globalPercentage = globalTotals.total > 0 ? Math.round((globalTotals.checked / globalTotals.total) * 100) : 0;

  return (
    <div style={{ overflowX: 'auto' }}>
      <table className="p-table">
        <thead>
          <tr>
            <th style={{ verticalAlign: "bottom" }}>Name</th>
            <th style={{ width: "20%", verticalAlign: "bottom" }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline' }}>
                <span>Global Progress</span>
                <span style={{ fontSize: "0.85em" }}>{globalPercentage}%</span>
              </div>
              <div className="u-progress-bar" style={{ marginTop: '4px', height: '4px' }}>
                <div className="u-progress-bar__fill" style={{ width: `${globalPercentage}%`, backgroundColor: getProgressColor(globalPercentage) }}></div>
              </div>
            </th>
            <th className="u-align--right">Total<br/><small>{globalTotals.total}</small></th>
            <th className="u-align--right">Translated<br/><small>{globalTotals.translated}</small></th>
            <th className="u-align--right">Disputed<br/><small>{globalTotals.disputed}</small></th>
            <th className="u-align--right">Checked<br/><small>{globalTotals.checked}</small></th>
            <th className="u-align--right">Reviewed<br/><small>{globalTotals.reviewed}</small></th>
          </tr>
        </thead>
        <tbody>
          {data.map((item, index) => (
            <TableRow key={index} item={item} />
          ))}
        </tbody>
      </table>
    </div>
  );
};

export default MultiTable;