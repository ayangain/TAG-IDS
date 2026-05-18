from neo4j import GraphDatabase
from tqdm import tqdm, trange
from collections import deque
import warnings
from pathlib import Path
warnings.simplefilter(action='ignore', category=FutureWarning)
# import pandas library as pd
import pandas as pd
import numpy as np
import networkx as nx
import os
import shutil
import pathlib
import getpass 
import platform
import math
import time
import glob
def strip_labels(graph):
    return {
        u: [v for (v, _) in edges]
        for u, edges in graph.items()
    }

def sparsify_and_replace():

    # --- Base directory logic ---
    if platform.system() == "Darwin":
        base_dir = Path(__file__).resolve().parent
    else:
        base_dir = Path(".").expanduser().resolve()

    print(f"Using base directory: {base_dir}")

    arc_files = glob.glob(str(base_dir / "ARCS_T*.CSV"))

    for arc_path in sorted(arc_files):
        arc_path = Path(arc_path)

        t = arc_path.stem.split("_")[1]
        vertex_path = base_dir / f"VERTICES_{t}.CSV"

        print(f"\nProcessing {t}...")

        arcs_df = pd.read_csv(arc_path)
        child_col = arcs_df.columns[0]
        parent_col = arcs_df.columns[1]

        # Build graph
        G = nx.DiGraph()
        for _, row in arcs_df.iterrows():
            G.add_edge(row[parent_col], row[child_col])

        print(f"[{t}] Original edges: {G.number_of_edges()}")

        # ===============================
        # 🔥 BALANCED REDUCTION LOGIC
        # ===============================

        MAX_OUT = 2  # strict control

        final_edges = set()
        visited = set()

        # sort nodes by out-degree (important nodes first)
        nodes_sorted = sorted(G.nodes(), key=lambda x: G.out_degree(x), reverse=True)

        for u in nodes_sorted:

            neighbors = list(G.successors(u))

            if not neighbors:
                continue

            # prioritize neighbors not yet visited (helps chain formation)
            neighbors_sorted = sorted(
                neighbors,
                key=lambda x: (x in visited, G.out_degree(x))
            )

            # take only top K
            selected = neighbors_sorted[:MAX_OUT]

            for v in selected:
                final_edges.add((u, v))
                visited.add(v)

        print(f"[{t}] Reduced edges: {len(final_edges)}")

        # --- OVERWRITE ARCS ---
        temp_arc_path = arc_path.with_suffix(".tmp")
        sparse_df = pd.DataFrame(list(final_edges), columns=[parent_col, child_col])
        sparse_df.to_csv(temp_arc_path, index=False)
        os.replace(temp_arc_path, arc_path)

        # --- UPDATE VERTICES ---
        if vertex_path.exists():
            vertices_df = pd.read_csv(vertex_path)
            node_col = vertices_df.columns[0]

            used_nodes = set()
            for u, v in final_edges:
                used_nodes.add(u)
                used_nodes.add(v)

            filtered_vertices = vertices_df[vertices_df[node_col].isin(used_nodes)]

            temp_vertex_path = vertex_path.with_suffix(".tmp")
            filtered_vertices.to_csv(temp_vertex_path, index=False)
            os.replace(temp_vertex_path, vertex_path)

        print(f"[{t}] Replaced original files ✅")


def prune_and_export_all():
    """
    Process all ARCS_Ti.CSV and VERTICES_Ti.CSV pairs in the given folder.
    Before exporting, move all original CSVs to a backup folder.
    """
    print(platform.system())

    if platform.system() == "Darwin":
        base_dir = Path(__file__).resolve().parent
    else:
        base_dir = Path(".").expanduser().resolve()

    # Backup originals
    backup_folder = os.path.join(base_dir, "backup_originals")
    os.makedirs(backup_folder, exist_ok=True)
    print(backup_folder)

    original_csvs = glob.glob(os.path.join(base_dir, "ARCS_T*.CSV")) + \
                    glob.glob(os.path.join(base_dir, "VERTICES_T*.CSV"))

    for f in original_csvs:
        dest = os.path.join(backup_folder, os.path.basename(f))
        if not os.path.exists(dest):
            shutil.move(f, dest)

    arcs_files = sorted(glob.glob(os.path.join(backup_folder, "ARCS_T*.CSV")))

    for arcs_path in arcs_files:
        suffix = arcs_path.split("ARCS_")[-1]
        suffix_clean = suffix.replace(".CSV", "").replace(".csv", "")

        vertices_path = arcs_path.replace("ARCS_", "VERTICES_")
        if not os.path.exists(vertices_path):
            continue

        arcs_df = pd.read_csv(arcs_path, header=None, names=["target", "source", "weight"])
        vertices_df = pd.read_csv(vertices_path, header=None, names=["id", "label", "type", "value"])

        # Build full graph
        G = nx.from_pandas_edgelist(arcs_df, source="source", target="target", create_using=nx.DiGraph())

        # --- Extract execCode nodes ---
        exec_nodes = {}
        for _, row in vertices_df.iterrows():
            if "execCode(" in str(row["label"]):
                node_id = row["id"]
                label = row["label"]
                exec_nodes[node_id] = label

        # --- Build reduced graph ---
        H = nx.DiGraph()

        exec_ids = list(exec_nodes.keys())

        for i in range(len(exec_ids)):
            for j in range(len(exec_ids)):
                if i == j:
                    continue

                src = exec_ids[i]
                tgt = exec_ids[j]

                if nx.has_path(G, src, tgt):
                    H.add_edge(src, tgt)

        # --- Prepare output ---
        final_edges = list(H.edges())

        arcs_out_df = pd.DataFrame(final_edges, columns=["source", "target"])
        arcs_out_df["weight"] = 1
        arcs_out_df = arcs_out_df[["target", "source", "weight"]]

        # Vertices: only execCode nodes
        vertices_out_df = vertices_df[vertices_df["id"].isin(exec_ids)].copy()

        # Output paths
        arcs_out = os.path.join(base_dir, f"ARCS_{suffix_clean}.CSV")
        vertices_out = os.path.join(base_dir, f"VERTICES_{suffix_clean}.CSV")

        arcs_out_df.to_csv(arcs_out, header=False, index=False)
        vertices_out_df.to_csv(vertices_out, header=False, index=False)

    print("✅ All graphs pruned and exported successfully.")

def copy_csv(dest):
    # path to source directory
    destination_folder=dest
    #source_folder = '/home/ayangain/.config/Neo4j Desktop/Application/relate-data/dbmss/dbms-1ec701b8-1e23-4252-bbfe-521a1ca8aeb9/import/'
    
    #print(destination_folder)
    # path to destination directory
    #destination_folder='/home/ayangain/Desktop/vs'
    source_folder = pathlib.Path(__file__).parent.resolve()
    source_folder=source_folder.__str__()
    #print(destination_folder)
    if platform.system() == 'Linux':
        source_folder=source_folder+'/'
        destination_folder=destination_folder+'/'
    elif platform.system() == 'Windows':
        source_folder=source_folder+'\\'
        destination_folder=destination_folder+'\\'
    else:
        source_folder=source_folder+'/'
        destination_folder=destination_folder+'/'
    #print(os.listdir(source_folder))
    # getting all the files in the source directory
    #print(destination_folder)
    counter=0
    for file_name in os.listdir(source_folder):
        # construct full file path
        source = source_folder + file_name
        destination = destination_folder + file_name
        extension = os.path.splitext(file_name)[1][1:]
        # copy only files
        if extension == "csv" or extension == "CSV":
            if os.path.isfile(source):
                shutil.copy(source, destination)
                counter+=1
    return counter

def clear_graph(tx):
    tx.run("match (n) detach delete n")
    tx.run("CALL gds.graph.drop('mygraph', false) YIELD graphName;")

def create_graph(tx):
    d=tx.run("CALL dbms.listConfig() YIELD name, value WHERE name = "+"'server.directories.import'"+" RETURN value;").value();
    d=d[0]
    print(d)
    total_files=copy_csv(d)
    total_graphs=int(math.ceil(total_files/2))
    Timestamps=[]
    File_names_arcs=[]
    File_names_vertices=[]
    for i in range(1,total_graphs+1):
        Timestamps.append('T'+str(i))
    for i in Timestamps:
        File_names_arcs.append("ARCS_"+i+".CSV")
        File_names_vertices.append("VERTICES_"+i+".CSV")
    for i,j in zip(File_names_vertices,Timestamps):
        tx.run("LOAD CSV FROM 'file:///"+i+"' AS row WITH toInteger(row[0]) AS id, row[1] AS fact, row[2] AS type WHERE type='AND' OR type = 'OR' MERGE (ag:"+j+" {id: id}) SET ag.fact = fact, ag.type = type RETURN count(ag); ")
    for i,j in zip(File_names_arcs,Timestamps):
        tx.run("LOAD CSV FROM 'file:///"+i+"' AS row  WITH toInteger(row[0]) AS   dst, toInteger(row[1]) AS src MATCH   (a:"+j+"),   (b:"+j+") WHERE a.id = src AND b.id = dst CREATE (a)-[r:arrow]->(b) RETURN type(r)")

    tx.run("CALL gds.graph.project(  'mygraph', "+str(Timestamps)+", ['arrow'] ) YIELD graphName AS graph, nodeProjection, nodeCount AS nodes, relationshipProjection, relationshipCount AS rels ")
    print("Temporal Attack Graph Created Successfully")

def Paths(session):
    label = session.run("MATCH (a) WITH DISTINCT LABELS(a) AS temp UNWIND temp AS label RETURN label").value()
    label.sort()
    nodes=[]
    for i in label: 
        t=session.run("MATCH (n:"+i+") RETURN n.id ")
        t=t.to_df()
        t = list(t['n.id'])
        nodes=nodes+t
    nodes=list(set(nodes))
    nextnode=None
    #timewindow=None
    # Initialize an empty adjacency list with the nodes
    adjacency_list = {node: [] for node in nodes}
    # print(dis)
    for i in label:
        for j in nodes:
            nextnode=None
            k=session.run("MATCH (startNode:"+i+"  {id: "+str(j)+"})-[:arrow]->(nextNode:"+i+") RETURN nextNode.id").value()
          
            if adjacency_list[j]:   
                # Retrieve the values 5 and 'T1'
                nextnode = [item[0] for item in adjacency_list[j]]
                
            if k and nextnode:
                new_k = k.copy()
                for item in new_k:
                    if item in nextnode:
                        k.remove(item)
           
            if k:
                k = list(zip(k, [i] * len(k)))
             
                if j in adjacency_list:
                    adjacency_list[j].extend(k)
            
    #print(label)
    return adjacency_list, label

def timewindow_first_occurence(session):
    label = session.run("MATCH (a) WITH DISTINCT LABELS(a) AS temp UNWIND temp AS label RETURN label").value()
    label.sort()
    nodes=[]
    result = []
    previous_numbers = set()
    for i in label: 
        t=session.run("MATCH (n:"+i+") RETURN n.id ").value()

        added_numbers = set(t) - set(previous_numbers)
        previous_numbers=list(previous_numbers)+list(added_numbers)

        result_list = list(zip(added_numbers, [i] * len(added_numbers)))

        result=result+result_list
    return result

def create_TAG(tx, adjacency_list,first_time):
    tx.run("match (n) detach delete n")
    tx.run("CALL gds.graph.drop('mygraph', false) YIELD graphName;")
    
    for node, neighbors in adjacency_list.items():
        tx.run("MERGE (p:TAG {name: "+str(node)+",time: '"+first_time[node]+"'}) return p.name").value()
    
    for node, neighbors in adjacency_list.items():
        for neighbor, rel_type in neighbors:
                tx.run("MATCH (p1:TAG ),(p2:TAG) WHERE p1.name="+str(node)+" AND p2.name = "+str(neighbor)+" CREATE (p1)-[r:"+rel_type+"]->(p2) RETURN type(r)")
def find_all_temporalpaths(session,label):
    direction = '>|'.join(label) + '>'
    query = (
            "MATCH (a:TAG) "
            "CALL apoc.path.expandConfig(a,{relationshipFilter: '"+direction+"',labelFilter:'TAG'}) YIELD path "
            "WITH DISTINCT [node IN nodes(path) | node.name] AS nodesOnPath, "
            "[rel IN relationships(path) | type(rel)] AS relationshipTypesOnPath "
            "WHERE all(i IN range(0, size(relationshipTypesOnPath)-2) WHERE relationshipTypesOnPath[i] <= relationshipTypesOnPath[i+1]) "
            "RETURN nodesOnPath, relationshipTypesOnPath"
            )
    result = session.run(query)
    result = result.to_df()
    return result

def find_direct_paths_df(df, node1, node2,label):
    result = []
    m = max(label)
    flag = 0
    for index, row in df.iterrows():
        path = row['nodesOnPath']
        first_element = path[0]
        last_element = path[-1]
        if first_element == node1 and last_element == node2:
            #print("HI")
            flag =1
            m=min((row['relationshipTypesOnPath'][-1]),m)
            result.append((path, row['relationshipTypesOnPath']))
    
    if flag == 0:
        m = None        
    #print(m)
    return m

def matrix(adjacency_list,label,result,first_time):
    Temporal_shortest_path = pd.DataFrame(columns=['Nodes'] + list(adjacency_list.keys()))
    Temporal_shortest_path['Nodes'] = adjacency_list.keys()
    for i in first_time:
        d_ij = int(''.join(filter(str.isdigit, i[1])))
        Temporal_shortest_path.loc[Temporal_shortest_path['Nodes'] == i[0], i[0]] = d_ij
    for i, neighbors in adjacency_list.items():
        for j, neighbors in adjacency_list.items():
            if i==j:
                continue
            direct_paths = find_direct_paths_df(result, i, j,label)
            if direct_paths != None:
                d_ij = int(''.join(filter(str.isdigit, direct_paths)))
                Temporal_shortest_path.loc[Temporal_shortest_path['Nodes'] == i, j] = d_ij
    return Temporal_shortest_path

def Temporal_Path_Length(df,adjacency_list):
    s=0
    s_l=0
    nodes=adjacency_list.keys()
    for i in range(len(df)-1):
        for j in nodes:
            s+=(1/df.loc[i, j])
            s_l+=df.loc[i, j]
    #df.to_csv('file12344.csv')
    tpe= (1/(len(nodes)*(len(nodes)-1)))*s
    tpl= (1/(len(nodes)*(len(nodes)-1)))*s_l
        
    print("Temporal Path Length = ",tpl)
    print("Temporal Path Efficiency = ",tpe)
    #print(df.iloc[:,-1:])
    return tpl,tpe,len(nodes)        

def Closeness_Centrality(adjacency_list,df,label):
    data_list = [{'Nodes': node, 'Closeness Centrality': None} for node in adjacency_list.keys()]
    cc=pd.DataFrame(data_list)
    temp = round((1/(len(label)*(len(adjacency_list.keys())-1))),4)
    #print(temp)
    for i in adjacency_list.keys():
            yo=df.loc[df['Nodes'] == i]
            yo = yo.drop(i, axis=1)
            #display(yo)
            k=list(yo.loc[yo['Nodes'] == i].iloc[0])
            k=k[1:]
            #print(k)
            c=0
            c=1-round(((temp)*sum(k)),8)
            #print(i,c)
            #cc.loc[len(cc.index)] = [int(i),c]
            y=np.where(cc['Nodes'] == i)[0]
            cc.loc[y[0],'Closeness Centrality'] = c
            yo.drop(yo.index, inplace=True)
    cc=cc.sort_values(by=['Closeness Centrality'], ascending=False)
    #display(cc)
    return cc


def calculate_betweenness(graph):
    BC = {v: 0.0 for v in graph}

    for s in graph:
        stack = []
        P = {v: [] for v in graph}
        sigma = {v: 0 for v in graph}
        dist = {v: -1 for v in graph}

        sigma[s] = 1
        dist[s] = 0
        Q = deque([s])

        # BFS
        while Q:
            v = Q.popleft()
            stack.append(v)
            for w in graph[v]:
                if dist[w] < 0:
                    Q.append(w)
                    dist[w] = dist[v] + 1
                if dist[w] == dist[v] + 1:
                    sigma[w] += sigma[v]
                    P[w].append(v)

        # Backpropagation
        delta = {v: 0 for v in graph}
        while stack:
            w = stack.pop()
            for v in P[w]:
                delta[v] += (sigma[v] / sigma[w]) * (1 + delta[w])
            if w != s:
                BC[w] += delta[w]

    # Normalize (directed)
    N = len(graph)
    for v in BC:
        BC[v] /= ((N - 1) * (N - 2))

    return pd.DataFrame(
        BC.items(),
        columns=["Nodes", "Betweenness Centrality"]
    ).sort_values("Betweenness Centrality", ascending=False)

driver = GraphDatabase.driver(
    "bolt://localhost:7687",
    auth=("neo4j", "12345678"),
    connection_timeout=300,
    max_connection_lifetime=3600,
    keep_alive=True
)

with driver.session() as session:
     prune_and_export_all()
     sparsify_and_replace()
     current_directory = pathlib.Path(__file__).parent.resolve()
     current_directory=current_directory.__str__()
     
     start = time.time()
     
     clear_graph(session)
     create_graph(session)
     
     adjacency_list,label=Paths(session)
     
     first_time=timewindow_first_occurence(session)
     time_node = {item[0]: item[1] for item in first_time}

     create_TAG(session,adjacency_list,time_node)
     result=find_all_temporalpaths(session,label)
     Temporal_shortest_path=matrix(adjacency_list,label,result,first_time)

     na = int(''.join(filter(str.isdigit, max(label))))

     Temporal_shortest_path = Temporal_shortest_path.fillna(na)
     tpl,tpe,nodes = Temporal_Path_Length(Temporal_shortest_path,adjacency_list)

     CC=Closeness_Centrality(adjacency_list,Temporal_shortest_path,label)
     print(CC)
     graph = strip_labels(adjacency_list)

     BC = calculate_betweenness(graph)
     print(BC)

     end = time.time()

     current_directory = pathlib.Path(__file__).parent.resolve()
     current_directory=current_directory.__str__()
     file_path = os.path.join(current_directory, 'output'+str(nodes)+'.csv')
     result = pd.merge(CC, BC, on='Nodes')
     result=result.sort_values(by=['Betweenness Centrality'], ascending=False)
     result.at[0, 'Temporal Path Length'] = tpl
     result.at[0, 'Temporal Path Efficiency'] = tpe

     result.to_csv(file_path, index=False)
     print(end - start,"seconds") 
    