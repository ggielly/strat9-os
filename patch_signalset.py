import re

with open('workspace/kernel/src/process/signal.rs', 'r') as f:
    content = f.read()

replacement = """
impl Clone for SignalSet {
    fn clone(&self) -> Self {
        Self::from_mask(self.get_mask())
    }
}

impl SignalSet {
"""

content = re.sub(r'impl SignalSet {\n', replacement, content)

with open('workspace/kernel/src/process/signal.rs', 'w') as f:
    f.write(content)
