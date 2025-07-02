import plotly.graph_objects as go
import networkx as nx
import pandas as pd
import plotly.express as px
import numpy as np

def plot_network(graph: nx.Graph, pos: dict, selected_nodes: tuple = (None, None)) -> go.Figure:
    """
    Plots the quantum network using Plotly.

    Args:
        graph (nx.Graph): The networkx graph.
        pos (dict): Dictionary of node positions.
        selected_nodes (tuple): A tuple (source_node, target_node) to highlight.

    Returns:
        go.Figure: A Plotly figure object.
    """
    edge_x = []
    edge_y = []
    for edge in graph.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_x.append(x0)
        edge_x.append(x1)
        edge_x.append(None)
        edge_y.append(y0)
        edge_y.append(y1)
        edge_y.append(None)

    edge_trace = go.Scatter(
        x=edge_x, y=edge_y,
        line=dict(width=0.5, color='#888'),
        hoverinfo='none',
        mode='lines')

    node_x = []
    node_y = []
    node_text = []
    node_colors = []
    for node in graph.nodes():
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)
        node_text.append(f"Node: {node}")
        if node == selected_nodes[0]:
            node_colors.append('red')
        elif node == selected_nodes[1]:
            node_colors.append('blue')
        else:
            node_colors.append('skyblue')

    node_trace = go.Scatter(
        x=node_x, y=node_y,
        mode='markers+text',
        hoverinfo='text',
        text=list(graph.nodes()), # Display node names as text
        textposition="bottom center",
        marker=dict(
            showscale=False,
            colorscale='YlGnBu',
            reversescale=True,
            color=node_colors,
            size=20,
            colorbar=dict(
                thickness=15,
                title='Node Connections',
                xanchor='left',
                titleside='right'
            ),
            line_width=2))

    fig = go.Figure(data=[edge_trace, node_trace],
                    layout=go.Layout(
                        title='<br>Quantum Network Topology',
                        titlefont_size=16,
                        showlegend=False,
                        hovermode='closest',
                        margin=dict(b=20, l=5, r=5, t=40),
                        annotations=[dict(
                            text="NetworkX layout",
                            showarrow=False,
                            xref="paper", yref="paper",
                            x=0.005, y=-0.002)],
                        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False))
                    )
    return fig

def visualize_bb84_process(alice_bits: np.ndarray, alice_bases: np.ndarray,
                           bob_bases: np.ndarray, bob_results: np.ndarray,
                           compatible_key_bits: np.ndarray) -> pd.DataFrame:
    """
    Creates a DataFrame to visualize the BB84 protocol step-by-step.
    """
    data = []
    shared_key_index = 0
    for i in range(len(alice_bits)):
        alice_polarization = ""
        if alice_bases[i] == 0: # Rectilinear
            alice_polarization = "↑" if alice_bits[i] == 0 else "↔"
        else: # Diagonal
            alice_polarization = "↗" if alice_bits[i] == 0 else "↘"

        bob_measurement_basis = ""
        if bob_bases[i] == 0: # Rectilinear
            bob_measurement_basis = "Rectilínea (+)"
        else: # Diagonal
            bob_measurement_basis = "Diagonal (x)"
        
        bob_measured_polarization = ""
        if bob_bases[i] == 0: # Rectilinear
            bob_measured_polarization = "↑" if bob_results[i] == 0 else "↔"
        else: # Diagonal
            bob_measured_polarization = "↗" if bob_results[i] == 0 else "↘"

        is_compatible = "No"
        shared_key_bit = ""
        if alice_bases[i] == bob_bases[i]:
            is_compatible = "Sí"
            if shared_key_index < len(compatible_key_bits):
                shared_key_bit = compatible_key_bits[shared_key_index]
                shared_key_index += 1

        data.append({
            "Paso": i + 1,
            "Bit Alice": alice_bits[i],
            "Base Alice": "Rectilínea (+)" if alice_bases[i] == 0 else "Diagonal (x)",
            "Polarización Enviada": alice_polarization,
            "Base Bob": bob_measurement_basis,
            "Resultado Medición Bob": bob_results[i],
            "Polarización Medida Bob": bob_measured_polarization,
            "Bases Compatibles": is_compatible,
            "Bit Clave Compartida": shared_key_bit
        })
    
    df = pd.DataFrame(data)
    return df

def plot_key_length_evolution(sessions_df: pd.DataFrame) -> go.Figure:
    """
    Plots the evolution of shared key length over time.

    Args:
        sessions_df (pd.DataFrame): DataFrame containing session history.

    Returns:
        go.Figure: A Plotly figure object.
    """
    if sessions_df.empty:
        fig = go.Figure()
        fig.add_annotation(text="No hay datos de sesiones para mostrar.",
                           xref="paper", yref="paper",
                           showarrow=False, font=dict(size=16))
        return fig

    # Ensure 'Timestamp' is datetime and sort
    sessions_df['Timestamp'] = pd.to_datetime(sessions_df['Timestamp'])
    sessions_df = sessions_df.sort_values(by='Timestamp')

    fig = px.line(sessions_df, x='Timestamp', y='Longitud Clave (bits)', color='Estado',
                  title='Evolución de la Longitud de Clave Compartida por Sesión',
                  labels={'Longitud Clave (bits)': 'Longitud de Clave (bits)', 'Timestamp': 'Tiempo'},
                  hover_data={'ID': True, 'Origen': True, 'Destino': True, 'Estado': True})
    
    fig.update_traces(mode='lines+markers')
    fig.update_layout(hovermode="x unified")
    fig.update_xaxes(
        rangeselector=dict(
            buttons=list([
                dict(count=1, label="1h", step="hour", stepmode="backward"),
                dict(count=1, label="1d", step="day", stepmode="backward"),
                dict(count=7, label="1w", step="day", stepmode="backward"),
                dict(step="all")
            ])
        ),
        rangeslider=dict(visible=True),
        type="date"
    )
    return fig
