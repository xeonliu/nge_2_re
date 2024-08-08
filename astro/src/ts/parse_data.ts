/* Data Structure from Paratranz */
// interface RawFile {
//     "id": number,
//     "createdAt": string,
//     "updatedAt": string,
//     "modifiedAt": string,
//     "name": string,
//     "total": number,
//     "translated": number,
//     "disputed": number,
//     "checked": number,
//     "reviewed": number,
//     "folder": string,
// }

/* Base Class for Component */
interface MyBaseFile {
    name: string,
    isLeaf: boolean,
    getContent: () => Array<MyBaseFile>;
    add: (file: MyBaseFile) => void;
    toJsonNode: () => string;
}


/* Component */
class MyFile implements MyBaseFile {
    name: string;
    isLeaf: boolean;
    total: number;
    translated: number;
    disputed: number;
    reviewed: number;

    constructor(raw) {
        this.isLeaf = true;
        let names = raw.name.split('/');
        this.name = names[names.length - 1].split('.')[0];
        this.total = raw.total;
        this.translated = raw.translated;
        this.disputed = raw.disputed;
        this.reviewed = raw.reviewed;
    }

    getContent() {
        return null;
    }

    add() {

    }

    toJsonNode() {
        return JSON.stringify(this);
    }
}

/* Composite */
class MyFolder implements MyBaseFile {
    name: string;
    isLeaf: boolean;
    content: Array<MyBaseFile>

    constructor(name: string) {
        this.name = name;
        this.isLeaf = false;
        this.content = [];
    }

    getContent() {
        return this.content;
    }

    add(file: MyBaseFile) {
        this.content.push(file);
    }

    toJsonNode() {
        const node = {
            name: this.name,
            isLeaf: this.isLeaf,
            children: this.content.map(child => child.toJsonNode())
        }

        return JSON.stringify(node);
    }
}

export default class MyProject {
    root: MyBaseFile;

    constructor() {
        this.root = new MyFolder("");
    }

    addRawFile(rawfile) {
        // Split the address of file.
        let folder_paths = rawfile.folder.split("/");

        let node = this.root;

        // Note: Nodes in paths are all folders!
        while (folder_paths.length > 0) {
            // Check if the folder exists.
            let folder = node.getContent().find((file) => file.name == folder_paths[0])
            
            if (folder == null) {
                // Create the folder and insert file in next level.
                folder = new MyFolder(folder_paths[0]);
                node.add(folder);
            }

            // remove the first element
            folder_paths.shift();
            node = folder;
        }

        // Paths contains nothing. Only File here.
        let file = new MyFile(rawfile);
        node.add(file);
    }

    test() {
        console.log(this.root.toJsonNode());
    }
}