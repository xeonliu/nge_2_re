import React from "react";

const MultiTable = ({ data }) => {
  return (
    <table border="1">
      <thead>
        <tr>
          <th>Name</th>
          <th>Total</th>
          <th>Translated</th>
          <th>Disputed</th>
          <th>Reviewed</th>
        </tr>
      </thead>
      <tbody>
        {data.map((item, index) => (
          <React.Fragment key={index}>
            <tr>
              <td>{item.name}</td>
              <td>{item.isLeaf ? item.total : "-"}</td>
              <td>{item.isLeaf ? item.translated : "-"}</td>
              <td>{item.isLeaf ? item.disputed : "-"}</td>
              <td>{item.isLeaf ? item.reviewed : "-"}</td>
            </tr>
            {!item.isLeaf && item.content && (
              <tr>
                <td colSpan="5">
                  <MultiTable data={item.content} />
                </td>
              </tr>
            )}
          </React.Fragment>
        ))}
      </tbody>
    </table>
  );
};

export default MultiTable;
