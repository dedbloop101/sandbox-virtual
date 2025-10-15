import streamlit as st
import os, json, uuid, subprocess
from pathlib import Path

# UPDATE THESE PATHS to match your project structure
BASE_DIR = Path.cwd()  # Current directory where your sandbox is
UPLOAD_DIR = BASE_DIR / "uploads"
RUNS_DIR = BASE_DIR / "runs"
POLICY_DIR = BASE_DIR / "policies"
SANDBOX_BIN = BASE_DIR / "sandbox_runner"  # Your compiled sandbox binary
RUN_TIMEOUT = 20

for d in (UPLOAD_DIR, RUNS_DIR, POLICY_DIR):
    d.mkdir(parents=True, exist_ok=True)

def set_bg(bg_color="linear-gradient(to bottom, #6a11cb, #2575fc)", opacity=0.85, sidebar_color="#4a148c"):
    st.markdown(
        f"""
        <style>
        .stApp {{
            background: {bg_color};
            background-attachment: fixed;
            background-size: cover;
            background-repeat: no-repeat;
        }}
        .stApp::before {{
            content: "";
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background-color: rgba(255, 255, 255, {opacity});
            z-index: -1;
        }}
        [data-testid="stSidebar"] {{
            background-color: {sidebar_color};
        }}
        [data-testid="stSidebar"] div {{
            color: white;
        }}
        .css-18e3th9 {{
            padding-top: 1rem;
        }}
        </style>
        """,
        unsafe_allow_html=True
    )

st.title("🛡 SafeZone Sandbox Dashboard")
page = st.sidebar.radio("Navigate", ["Home", "Upload & Run", "Policies", "Runs"])

if page == "Home":
    set_bg("linear-gradient(to bottom right, #7b2ff7, #f107a3)", opacity=0.85, sidebar_color="#7b1fa2")
    st.subheader("Welcome to SafeZone Dashboard")
    st.markdown("""
    ### Features:
    - 📤 **Upload** untrusted programs safely  
    - ⚙️ **Configure** sandbox policies (memory, CPU, network, syscalls)  
    - 🔍 **View** execution logs & reports  
    - 🛡️ **Isolate** programs using cgroups + seccomp
    
    ### How to use:
    1. Go to **Policies** to create or view security policies
    2. Go to **Upload & Run** to test a program in the sandbox
    3. Check **Runs** to see previous execution results
    """)
    
    # Show system status
    st.subheader("System Status")
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Sandbox Binary", "✅ Found" if SANDBOX_BIN.exists() else "❌ Missing")
    with col2:
        st.metric("Policies", len(list(POLICY_DIR.glob("*.json"))))
    with col3:
        st.metric("Previous Runs", len(list(RUNS_DIR.glob("*"))))

elif page == "Policies":
    set_bg("linear-gradient(to right, #8e2de2, #4a00e0)", opacity=0.85, sidebar_color="#4a148c")
    st.subheader("Manage Policies")

    # List existing policies
    pols = list(POLICY_DIR.glob("*.json"))
    if pols:
        st.write("### Existing Policies:")
        for p in pols:
            with st.expander(f"📄 {p.name}"):
                st.json(json.loads(p.read_text()))
            if st.button(f"Delete {p.name}", key=f"del_{p.name}"):
                p.unlink()
                st.rerun()
    else:
        st.info("No policies yet. Create one below!")

    st.write("---")
    st.write("### Create New Policy")
    
    policy_name = st.text_input("Policy Name", "my_policy").replace(" ", "_").replace(".json", "")
    
    # Policy template that matches your C structure
    default_policy = {
        "resources": {
            "memory_bytes": 536870912,  # 512 MB
            "cpu_quota_us": 1000000     # 100% of CPU
        },
        "network": {"allow": False},
        "syscalls": {"deny": ["reboot", "init_module", "mount", "umount2"]}
    }
    
    edited_policy = st.text_area(
        "Policy JSON", 
        json.dumps(default_policy, indent=2), 
        height=300
    )
    
    if st.button("Save Policy"):
        try:
            # Validate JSON
            policy_obj = json.loads(edited_policy)
            policy_path = POLICY_DIR / f"{policy_name}.json"
            
            # Save the policy
            with open(policy_path, "w") as f:
                json.dump(policy_obj, f, indent=2)
            
            st.success(f"✅ Policy saved as {policy_name}.json")
            st.rerun()
            
        except json.JSONDecodeError as e:
            st.error(f"❌ Invalid JSON: {e}")
        except Exception as e:
            st.error(f"❌ Error saving policy: {e}")

elif page == "Upload & Run":
    set_bg("linear-gradient(to top right, #6a11cb, #2575fc)", opacity=0.85, sidebar_color="#4a148c")
    st.subheader("Upload & Run Program in Sandbox")

    # Check if sandbox binary exists
    if not SANDBOX_BIN.exists():
        st.error(f"❌ Sandbox binary not found at {SANDBOX_BIN}")
        st.info("Please compile the sandbox first: `make`")
        st.stop()

    # Get available policies
    policies = [p.name for p in POLICY_DIR.glob("*.json")]
    if not policies:
        st.error("No policies available. Please create a policy first.")
        st.stop()

    # File upload
    uploaded_file = st.file_uploader("Choose a program to run", type=None)
    
    # Policy selection
    selected_policy = st.selectbox("Select Security Policy", policies)
    
    # Use sudo option
    use_sudo = st.checkbox("Use sudo for cgroups (recommended)", value=True)

    if st.button("🚀 Run in Sandbox") and uploaded_file:
        # Create unique run ID
        run_id = uuid.uuid4().hex[:8]
        run_path = RUNS_DIR / run_id
        run_path.mkdir(parents=True, exist_ok=True)
        
        # Save uploaded program
        prog_path = run_path / "program"
        with open(prog_path, "wb") as f:
            f.write(uploaded_file.getbuffer())
        
        # Make executable
        prog_path.chmod(0o755)
        
        # Get policy path
        policy_path = POLICY_DIR / selected_policy
        
        st.info(f"Running sandbox with ID: {run_id}")
        
        # Build command
        cmd = [str(SANDBOX_BIN), str(prog_path), str(run_path), str(policy_path)]
        if use_sudo:
            cmd = ["sudo"] + cmd
        
        st.write("### Execution Details")
        st.code(" ".join(cmd))
        
        # Run sandbox
        try:
            result = subprocess.run(
                cmd,
                timeout=RUN_TIMEOUT,
                capture_output=True,
                text=True
            )
            
            # Display results
            st.write("### Sandbox Output")
            st.code(result.stdout)
            
            if result.stderr:
                st.write("### Sandbox Errors")
                st.code(result.stderr)
            
            # Show program output
            stdout_file = run_path / "stdout.log"
            stderr_file = run_path / "stderr.log"
            
            if stdout_file.exists():
                st.write("### Program Output")
                stdout_content = stdout_file.read_text()
                st.code(stdout_content if stdout_content else "(empty)")
            
            if stderr_file.exists():
                st.write("### Program Errors")
                stderr_content = stderr_file.read_text()
                st.code(stderr_content if stderr_content else "(empty)")
            
            # Download buttons
            col1, col2 = st.columns(2)
            with col1:
                if stdout_file.exists():
                    st.download_button(
                        "📥 Download Stdout",
                        stdout_file.read_text(),
                        f"stdout_{run_id}.log"
                    )
            with col2:
                if stderr_file.exists():
                    st.download_button(
                        "📥 Download Stderr", 
                        stderr_file.read_text(),
                        f"stderr_{run_id}.log"
                    )
                        
        except subprocess.TimeoutExpired:
            st.error("⏰ Sandbox execution timed out")
        except Exception as e:
            st.error(f"❌ Error running sandbox: {e}")

elif page == "Runs":
    set_bg("linear-gradient(to bottom left, #9d50bb, #6e48aa)", opacity=0.85, sidebar_color="#4a148c")
    st.subheader("Previous Runs")
    
    runs = sorted(RUNS_DIR.glob("*"), key=os.path.getctime, reverse=True)
    
    if not runs:
        st.info("No runs yet. Go to 'Upload & Run' to test a program!")
    else:
        for run_path in runs[:10]:  # Show last 10 runs
            with st.expander(f"Run: {run_path.name} ({run_path.stat().st_ctime:.1f})"):
                stdout_file = run_path / "stdout.log"
                stderr_file = run_path / "stderr.log"
                
                if stdout_file.exists():
                    st.write("**Program Output:**")
                    st.code(stdout_file.read_text())
                
                if stderr_file.exists():
                    st.write("**Program Errors:**")
                    st.code(stderr_file.read_text())
                
                # Show files in run directory
                st.write("**Run Files:**")
                for f in run_path.iterdir():
                    st.write(f"- {f.name} ({f.stat().st_size} bytes)")