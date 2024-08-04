from tools.hgar import HGArchive,HGArchiveFile;

class AdvancedHGArchive(HGArchive):
    def __init__(self):
        self.filename = 'undefined'
        super().__init__()