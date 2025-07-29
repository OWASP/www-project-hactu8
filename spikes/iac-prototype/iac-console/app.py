
import os
import streamlit as st
from dotenv import load_dotenv
import openai

# Load environment variables from .env
load_dotenv()

openai_api_key = os.getenv("OPENAI_API_KEY")
client = openai.OpenAI(api_key=openai_api_key)

st.set_page_config(page_title="OpenAI Chat", page_icon="🤖")
# st.title("OpenAI Chatbot 🤖")

if "messages" not in st.session_state:
    st.session_state["messages"] = []

for msg in st.session_state["messages"]:
    with st.chat_message(msg["role"]):
        st.markdown(msg["content"])

if prompt := st.chat_input("Say something..."):
    st.session_state["messages"].append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)
    try:
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[{"role": m["role"], "content": m["content"]} for m in st.session_state["messages"]]
        )
        reply = response.choices[0].message.content if response.choices[0].message.content else "(No response from model)"
    except Exception as e:
        reply = f"Error: {e}"
    st.session_state["messages"].append({"role": "assistant", "content": reply})
    with st.chat_message("assistant"):
        st.markdown(reply)
