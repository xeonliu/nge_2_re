import React from "react";
import leaderboard from "../../data/leaderboard.json";
import "./MultiTable.css";

const LeaderboardTable = () => {
  // 按 points 降序排序
  const sorted = [...leaderboard].sort((a, b) => b.points - a.points);
  return (
    <div style={{ overflowX: 'auto', marginTop: '2rem' }}>
      <h2>贡献榜</h2>
      <table className="p-table">
        <thead>
          <tr>
            {/* <th>排名</th> */}
            <th>昵称</th>
            {/* <th>用户名</th> */}
            {/* <th>头像</th> */}
            <th>翻译 + 编辑</th>
            <th>审核</th>
            <th>积分</th>
            {/* <th>最近活跃</th> */}
          </tr>
        </thead>
        <tbody>
          {sorted.map((user, idx) => (
            <tr key={user.id}>
              {/* <td>{idx + 1}</td> */}
              <td>{user.nickname || user.username}</td>
              {/* <td>{user.username}</td> */}
              {/* <td>
                <img src={user.avatar} alt={user.username} style={{ width: 32, height: 32, borderRadius: '50%' }} />
              </td> */}
              <td>{user.translated + user.edited}</td>
              <td>{user.reviewed}</td>
              <td>{user.points}</td>
              {/* <td>{user.lastVisit ? new Date(user.lastVisit).toLocaleString() : ''}</td> */}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

export default LeaderboardTable;
