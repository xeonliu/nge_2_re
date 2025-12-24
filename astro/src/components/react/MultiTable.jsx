import React, { useState, useMemo } from "react";
import "./MultiTable.css";

// 提取颜色逻辑，供 TableRow 和 MultiTable 共同使用
const getProgressColor = (percentage) => {
  if (percentage < 33) return "#c7162b"; // Vanilla Negative
  if (percentage < 66) return "#ed6c02"; // Vanilla Warning
  return "#0e8a16"; // Vanilla Positive
};

const TableRow = ({ item, depth = 0 }) => {
  const [isExpanded, setIsExpanded] = useState(false);

  const toggleExpand = () => setIsExpanded(!isExpanded);

  const percentage = item.total > 0 ? Math.round((item.checked / item.total) * 100) : 0;
  const hasChildren = !item.isLeaf && item.content && item.content.length > 0;

  return (
    <>
      <tr 
        className={hasChildren ? "is-clickable" : ""} 
        onClick={hasChildren ? toggleExpand : undefined} 
        style={{ cursor: hasChildren ? 'pointer' : 'default' }}
      >
        <td style={{ paddingLeft: `${depth * 1.5 + 0.5}rem` }}>
          <div className="u-flex-center">
            {hasChildren ? (
              <button 
                className="u-no-border u-cursor-pointer"
                onClick={(e) => { e.stopPropagation(); toggleExpand(); }}
                aria-label={isExpanded ? "Collapse" : "Expand"}
                style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', width: '1rem', background: 'transparent' }}
              >
                <i className={isExpanded ? "p-icon--chevron-down" : "p-icon--chevron-right"}></i>
              </button>
            ) : (
              <span style={{ width: "1rem", display: "inline-block" }}></span>
            )}
            <span style={{ fontWeight: hasChildren ? "600" : "400", marginLeft: "0.5rem" }}>{item.name}</span>
          </div>
        </td>
        <td>
          {item.isLeaf ? (
            <div>
              <div style={{ fontSize: "0.85em", marginBottom: "2px" }}>{percentage}%</div>
              <div className="u-progress-bar">
                <div 
                  className="u-progress-bar__fill" 
                  style={{ 
                    width: `${percentage}%`, 
                    backgroundColor: getProgressColor(percentage) 
                  }}
                ></div>
              </div>
            </div>
          ) : "-"}
        </td>
        <td className="u-align--right">{item.isLeaf ? item.total : "-"}</td>
        <td className="u-align--right">{item.isLeaf ? item.translated : "-"}</td>
        <td className="u-align--right">{item.isLeaf ? item.disputed : "-"}</td>
        <td className="u-align--right">{item.isLeaf ? item.checked : "-"}</td>
        <td className="u-align--right">{item.isLeaf ? item.reviewed : "-"}</td>
      </tr>
      {isExpanded && hasChildren && item.content.map((child, index) => (
        <TableRow key={index} item={child} depth={depth + 1} />
      ))}
    </>
  );
};

const MultiTable = ({ data }) => {
  // 1. 递归计算所有叶子节点的总和
  const totals = useMemo(() => {
    const stats = { total: 0, translated: 0, disputed: 0, checked: 0, reviewed: 0 };

    const traverse = (nodes) => {
      nodes.forEach((node) => {
        if (node.isLeaf) {
          stats.total += node.total || 0;
          stats.translated += node.translated || 0;
          stats.disputed += node.disputed || 0;
          stats.checked += node.checked || 0;
          stats.reviewed += node.reviewed || 0;
        } else if (node.content && node.content.length > 0) {
          traverse(node.content);
        }
      });
    };

    traverse(data);
    return stats;
  }, [data]);

  // 2. 计算全局百分比
  const totalPercentage = totals.total > 0 ? Math.round((totals.checked / totals.total) * 100) : 0;

  return (
    <div style={{ overflowX: 'auto' }}>
      <table className="p-table">
        <thead>
          <tr>
            <th style={{ verticalAlign: "bottom" }}>Name</th>
            
            {/* 进度条表头：显示全局进度 */}
            <th style={{ width: "25%", verticalAlign: "bottom" }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline' }}>
                <span>Progress</span>
                <span style={{ fontSize: "0.85em", fontWeight: "normal" }}>{totalPercentage}%</span>
              </div>
              <div className="u-progress-bar" style={{ marginTop: '4px', height: '4px' }}>
                <div 
                  className="u-progress-bar__fill" 
                  style={{ 
                    width: `${totalPercentage}%`, 
                    backgroundColor: getProgressColor(totalPercentage) 
                  }}
                ></div>
              </div>
            </th>

            {/* 数值表头：显示名称和下方的总数 */}
            <th className="u-align--right" style={{ verticalAlign: "bottom" }}>
              <div>Total</div>
              <div style={{ fontSize: "1.1em", fontWeight: "300", marginTop: "4px" }}>{totals.total}</div>
            </th>
            <th className="u-align--right" style={{ verticalAlign: "bottom" }}>
              <div>Translated</div>
              <div style={{ fontSize: "1.1em", fontWeight: "300", marginTop: "4px" }}>{totals.translated}</div>
            </th>
            <th className="u-align--right" style={{ verticalAlign: "bottom" }}>
              <div>Disputed</div>
              <div style={{ fontSize: "1.1em", fontWeight: "300", marginTop: "4px" }}>{totals.disputed}</div>
            </th>
            <th className="u-align--right" style={{ verticalAlign: "bottom" }}>
              <div>Checked</div>
              <div style={{ fontSize: "1.1em", fontWeight: "300", marginTop: "4px" }}>{totals.checked}</div>
            </th>
            <th className="u-align--right" style={{ verticalAlign: "bottom" }}>
              <div>Reviewed</div>
              <div style={{ fontSize: "1.1em", fontWeight: "300", marginTop: "4px" }}>{totals.reviewed}</div>
            </th>
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