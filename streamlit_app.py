import streamlit as st
import pandas as pd
from datetime import datetime
from sqlalchemy import create_engine, text
from passlib.context import CryptContext
import os

# Připojovací údaje (lze později nahradit načítáním z .env)
DB_USER = "neondb_owner"
DB_PASSWORD = "npg_bqIR6D2UkALc"
DB_HOST = "ep-icy-moon-a2bfjmyb-pooler.eu-central-1.aws.neon.tech"
DB_NAME = "neondb"

@st.cache_resource
def get_engine():
    conn_str = f"postgresql+psycopg2://{DB_USER}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}"
    return create_engine(conn_str, connect_args={"sslmode": "require"})

# Kontext pro hesla
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

# Přihlášení
def check_login(email: str, password: str, conn) -> str | None:
    result = conn.execute(
        text("SELECT password_hash, role FROM auth.users WHERE email = :email"),
        {"email": email}
    ).fetchone()
    if not result:
        return None
    stored_hash, role = result
    if verify_password(password, stored_hash):
        return role
    return None

def login_form():
    st.subheader("Přihlášení")
    with st.form("login_form"):
        email = st.text_input("Email")
        password = st.text_input("Heslo", type="password")
        submitted = st.form_submit_button("Přihlásit")
    if submitted:
        with engine.begin() as conn:
            role = check_login(email, password, conn)
        if role:
            st.session_state.logged_in = True
            st.session_state.user_email = email
            st.session_state.user_role = role
            st.success(f"Přihlášen jako {email} ({role})")
            st.rerun()
        else:
            st.error("Neplatné přihlašovací údaje")

# Registrace
def register_form():
    st.subheader("Registrace")
    with st.form("register_form"):
        email = st.text_input("Email")
        password = st.text_input("Heslo", type="password")
        confirm = st.text_input("Potvrzení hesla", type="password")
        role = st.selectbox("Role", ["viewer", "editor"])
        submitted = st.form_submit_button("Registrovat")
    if submitted:
        if password != confirm:
            st.error("Hesla se neshodují")
            return
        hashed = hash_password(password)
        try:
            with engine.begin() as conn:
                conn.execute(
                    text("INSERT INTO auth.users (email, password_hash, role) VALUES (:email, :hash, :role)"),
                    {"email": email, "hash": hashed, "role": role}
                )
            st.success("Registrace proběhla úspěšně, nyní se přihlaste.")
        except Exception as e:
            st.error(f"Chyba: {e}")

# Změna hesla
def change_password_form():
    st.subheader("Změna hesla")
    with st.form("change_password_form"):
        old_password = st.text_input("Staré heslo", type="password")
        new_password = st.text_input("Nové heslo", type="password")
        confirm = st.text_input("Potvrzení nového hesla", type="password")
        submitted = st.form_submit_button("Změnit heslo")
    if submitted:
        if new_password != confirm:
            st.error("Nová hesla se neshodují")
            return
        with engine.begin() as conn:
            # Ověření starého hesla
            role = check_login(st.session_state.user_email, old_password, conn)
            if not role:
                st.error("Staré heslo není správné")
                return
            # Aktualizace
            hashed = hash_password(new_password)
            conn.execute(
                text("UPDATE auth.users SET password_hash = :hash WHERE email = :email"),
                {"hash": hashed, "email": st.session_state.user_email}
            )
        st.success("Heslo bylo změněno")

# Odhlášení
def logout():
    if st.button("Odhlásit", use_container_width=True):
        st.session_state.clear()
        st.rerun()

# Viewer
def viewer_ui():
    st.subheader("Zobrazení dat")
    with engine.begin() as conn:
        df = pd.read_sql("SELECT * FROM cars.vehicles ORDER BY id", conn)
    st.dataframe(df)

# Editor
def editor_ui():
    viewer_ui()
    st.subheader("Import dat (jen pro editory)")
    uploaded_file = st.file_uploader("Vyber CSV soubor", type="csv")
    if uploaded_file and st.button("Importovat", use_container_width=True):
        df = pd.read_csv(uploaded_file)
        with engine.begin() as conn:
            df.to_sql("vehicles", conn, schema="cars", if_exists="append", index=False)
        st.success("Data importována.")

# Hlavní funkce
def main():
    engine = get_engine()

    st.title("Databázová aplikace s autentizací")

    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False

    if st.session_state.logged_in:
        st.write(f"👤 {st.session_state.user_email} ({st.session_state.user_role})")
        logout()
        change_password_form()
        role = st.session_state.user_role
        if role == "viewer":
            viewer_ui()
        elif role == "editor":
            editor_ui()
        else:
            st.error("Neznámá role")
    else:
        page = st.radio("Vyber akci", ["Přihlášení", "Registrace"])
        if page == "Přihlášení":
            login_form()
        else:
            register_form()

if __name__ == "__main__":
    main()
