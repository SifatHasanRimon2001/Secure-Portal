from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    String,
    Text,
    DateTime,
    ForeignKey,
    func
)
from sqlalchemy.orm import (
    DeclarativeBase,
    relationship,
    scoped_session,
    sessionmaker
)


class Base(DeclarativeBase):
    """Base class for all models."""


class _QueryProperty:
    """Descriptor that recreates a query each time it is accessed
    (mimics Flask-SQLAlchemy's Model.query pattern)."""

    def __get__(self, obj, objtype):
        return db.session.query(objtype)


class _DB:
    """Database helper that provides a Flask-SQLAlchemy-like interface.

    Exposes commonly-used names at the top level so existing model and
    service code continues to work without major rewrites.
    """

    def __init__(self):
        self.Model = Base
        self.Column = Column
        self.Integer = Integer
        self.String = String
        self.Text = Text
        self.DateTime = DateTime
        self.ForeignKey = ForeignKey
        self.relationship = relationship
        self.func = func
        self.engine = None
        self._session_factory = None
        self.session = None

    def init_app(self, database_url: str) -> None:
        """Initialise the database engine and scoped session."""
        self.engine = create_engine(database_url, echo=False)
        self._session_factory = sessionmaker(bind=self.engine)
        self.session = scoped_session(self._session_factory)

    def create_all(self) -> None:
        """Create all tables registered on Base."""
        Base.metadata.create_all(bind=self.engine)

    def drop_all(self) -> None:
        """Drop all tables (useful in tests)."""
        Base.metadata.drop_all(bind=self.engine)


db = _DB()

# Attach the query property to Base so every model gets ``.query``
Base.query = _QueryProperty()
