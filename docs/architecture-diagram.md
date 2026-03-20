# Architecture Diagram — Prometheus Atlas

## System Flow

    User  
     ↓  
    CLI  
     ↓  
  Discovery  
     ↓  
  Snapshot  
     ↓  
    Diff  
     ↓  
    Drift  
     ↓  
 Correlation  
     ↓  
  Episodes  
     ↓  
   Store  
     ↓      
   Output  

---

## Layers

1. Interface → CLI  
2. Discovery → DNS + HTTP  
3. State → Snapshots  
4. Diff → Comparison  
5. Drift → Intelligence  
6. Correlation → Grouping  
7. Episodes → Events  
8. Storage → SQLite  
9. Output → Reports  

---

## Future

- backend API
- distributed workers
- frontend