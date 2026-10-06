"""Compatibility entry point for rebuilding the supported knowledge collections."""
from .rebuild_rag import rebuild_all_collections


def init_vector_db():
    rebuild_all_collections()


if __name__ == '__main__':
    init_vector_db()
