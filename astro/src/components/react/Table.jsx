import json from "../../data/files.json";

// Group Files in Folders.

function generateFileGroup(files) {
  let group = [];
  for (const file of files) {
    let folder = group.find((folder) => folder.name == file.folder);
    if (folder != null) {
      folder["content"].push(file);
    } else {
      group.push({ name: file.folder, content: [] });
    }
  }
  console.log(group);
  return group;
}
const headers = [
  { content: null },
  { content: "文件夹" },
  { content: "总条数" },
];

const file_group = generateFileGroup(json);

const Table = () => {
  return (
    <table aria-label="Vanilla framework table example">
      <thead>
        <tr>
          <th>文件夹名</th>
          <th>已翻译/总条数</th>
          <th>已审核/总条数</th>
        </tr>
      </thead>
      <tbody>
        {file_group.map((folder) => (
          <tr>
            <th>{folder.name}</th>
            <th>
              {folder.content.reduce(
                (old, current) => old + current.translated,
                0
              )}
              /{folder.content.reduce((old, current) => old + current.total, 0)}
            </th>
            <th>
              {folder.content.reduce(
                (old, current) => old + current.reviewed,
                0
              )}
              /{folder.content.reduce((old, current) => old + current.total, 0)}
            </th>
          </tr>
        ))}
      </tbody>
      <tfoot>
        <tr>
          <th>合计</th>
          <td>
            {json.reduce((old, curr) => old + curr.translated, 0)}/
            {json.reduce((old, curr) => old + curr.total, 0)}
          </td>
          <td>
            {json.reduce((old, curr) => old + curr.reviewed, 0)}/
            {json.reduce((old, curr) => old + curr.total, 0)}
          </td>
        </tr>
      </tfoot>
    </table>
  );
};

export default Table;
