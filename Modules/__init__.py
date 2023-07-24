from .SQLInjection import SQLInjection
from .CrossSiteScripting import CrossSiteScripting
from .CommandInjection import CommandInjection
from .FileInclusion import FileInclusion
from .OpenRedirect import OpenRedirect
from .UnrestrictedFileUpload import UnrestrictedFileUpload
from .PathTraversal import PathTraversal
from .ArbitraryFileDeletion import ArbitraryFileDeletion
from .PHPObjectInjection import PHPObjectInjection

classes = {
    'CommandInjection': CommandInjection,
    'CrossSiteScripting': CrossSiteScripting,
    'FileInclusion': FileInclusion,
    'ArbitraryFileDeletion': ArbitraryFileDeletion,
    'OpenRedirect': OpenRedirect,
    'PathTraversal': PathTraversal,
    'PHPObjectInjection': PHPObjectInjection,
    'SQLInjection': SQLInjection,
    'UnrestrictedFileUpload': UnrestrictedFileUpload
}
