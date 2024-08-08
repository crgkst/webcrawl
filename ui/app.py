import streamlit as st
import pandas as pd
import networkx as nx
from pyvis.network import Network
from collections import defaultdict
from sqlalchemy import create_engine, text, func, TIMESTAMP
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.dialects.mysql import LONGTEXT, TEXT
import os
from urllib.parse import urlparse
import tempfile


DATABASE_URL = os.environ.get('DATABASE_URL')
engine = create_engine(DATABASE_URL)

Base = declarative_base()

class Website(Base):
    __tablename__ = 'websites'
    id = Column(Integer, primary_key=True)
    url = Column(String(255), unique=True, nullable=False)
    status = Column(String(20), default='pending')
    parent_url = Column(String(255))

class Page(Base):
    __tablename__ = 'pages'
    id = Column(Integer, primary_key=True)
    url = Column(String(255), unique=True, nullable=False)
    content = Column(LONGTEXT)
    status = Column(String(20), default='pending')
    website_id = Column(Integer, ForeignKey('websites.id'))

class Email(Base):
    __tablename__ = 'emails'
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, nullable=False)
    source_url = Column(String(255), ForeignKey('websites.url'), nullable=False)

class Blacklist(Base):
    __tablename__ = 'blacklist'
    id = Column(Integer, primary_key=True)
    domain = Column(String(255), unique=True, nullable=False)
    reason = Column(String(255))
    date_added = Column(TIMESTAMP, server_default=func.now())


Session = sessionmaker(bind=engine)

def is_crawler_enabled():
    return os.path.exists('/app/control/crawler_enabled')

def enable_crawler():
    with open('/app/control/crawler_enabled', 'w') as f:
        f.write('enabled')

def disable_crawler():
    if os.path.exists('/app/control/crawler_enabled'):
        os.remove('/app/control/crawler_enabled')


def get_top_level_domain(url):
    parsed_url = urlparse(url)
    domain_parts = parsed_url.netloc.split('.')
    if len(domain_parts) > 2:
        return f"{domain_parts[-2]}.{domain_parts[-1]}"
    return parsed_url.netloc

def get_websites():
    with engine.connect() as conn:
        websites = pd.read_sql(text('SELECT * FROM websites'), conn)
        websites['domain'] = websites['url'].apply(get_top_level_domain)
        return websites

def get_domain_websites(domain):
    with engine.connect() as conn:
        query = text('''
            SELECT w.*, p.content, p.status as page_status
            FROM websites w
            LEFT JOIN pages p ON w.url = p.url
            WHERE w.url LIKE :domain_pattern
        ''')
        return pd.read_sql(query, conn, params={'domain_pattern': f'%{domain}%'})

def get_emails():
    with engine.connect() as conn:
        return pd.read_sql(text('SELECT * FROM emails'), conn)

def add_website(url):
    session = Session()
    try:
        new_website = Website(url=url, status='pending')
        session.add(new_website)
        session.commit()
        st.success(f'Added {url} to the crawl queue.')
    except Exception as e:
        st.error(f"An error occurred: {str(e)}")
    finally:
        session.close()

def rerun_website(website_id):
    session = Session()
    try:
        website = session.query(Website).get(website_id)
        if website:
            session.query(Page).filter_by(website_id=website_id).delete()
            website.status = 'pending'
            session.commit()
            st.success(f'Website {website.url} has been queued for re-crawling.')
        else:
            st.error('Website not found.')
    except Exception as e:
        st.error(f"An error occurred: {str(e)}")
    finally:
        session.close()

def get_website_links(domain):
    with engine.connect() as conn:
        query = text('''
            SELECT w.url AS source, w2.url AS target
            FROM websites w
            JOIN websites w2 ON w2.parent_url = w.url
            WHERE w.url LIKE :domain_pattern OR w2.url LIKE :domain_pattern
        ''')
        return pd.read_sql(query, conn, params={'domain_pattern': f'%{domain}%'})

def create_website_graph(links_df, max_nodes=100):
    G = nx.DiGraph()
    for _, row in links_df.iterrows():
        G.add_edge(row['source'], row['target'])

    if len(G.nodes) > max_nodes:
        # If the graph is too large, we'll limit it to the most connected nodes
        sorted_nodes = sorted(G.degree, key=lambda x: x[1], reverse=True)
        top_nodes = [node for node, _ in sorted_nodes[:max_nodes]]
        G = G.subgraph(top_nodes)

    net = Network(height="500px", width="100%", directed=True)

    for node in G.nodes():
        net.add_node(node, label=node)

    for edge in G.edges():
        net.add_edge(edge[0], edge[1])

    return net

def get_blacklist():
    with engine.connect() as conn:
        return pd.read_sql(text('SELECT * FROM blacklist'), conn)

def add_to_blacklist(domain, reason):
    session = Session()
    try:
        blacklist_entry = Blacklist(domain=domain, reason=reason)
        session.add(blacklist_entry)
        session.commit()
        st.success(f'Added {domain} to the blacklist.')
    except Exception as e:
        st.error(f"An error occurred: {str(e)}")
    finally:
        session.close()

def remove_from_blacklist(domain):
    session = Session()
    try:
        session.query(Blacklist).filter_by(domain=domain).delete()
        session.commit()
        st.success(f'Removed {domain} from the blacklist.')
    except Exception as e:
        st.error(f"An error occurred: {str(e)}")
    finally:
        session.close()


def get_all_websites():
    with engine.connect() as conn:
        return pd.read_sql(text('SELECT * FROM websites'), conn)

def get_total_websites():
    with engine.connect() as conn:
        return pd.read_sql(text('SELECT COUNT(*) as count FROM websites'), conn).iloc[0]['count']

def get_root_websites():
    with engine.connect() as conn:
        return pd.read_sql(text('SELECT * FROM websites WHERE parent_url IS NULL OR parent_url = ""'), conn)

def create_simplified_network_graph(domain_summary):
    G = nx.Graph()

    for domain, data in domain_summary.items():
        total_count = data['count']
        completed_count = data['status'].get('completed', 0)
        completion_ratio = completed_count / total_count if total_count > 0 else 0

        # Determine node color based on completion ratio and root status
        if data['is_root']:
            color = '#FF0000'  # Red for root pages
            size = min(70, 20 + (total_count // 5))  # Larger size for root pages
        elif completion_ratio == 1:
            color = '#32CD32'  # Green for fully completed
            size = min(50, 5 + (total_count // 10))
        elif completion_ratio > 0.5:
            color = '#FFA500'  # Orange for mostly completed
            size = min(50, 5 + (total_count // 10))
        else:
            color = '#4169E1'  # Blue for less than half completed
            size = min(50, 5 + (total_count // 10))

        G.add_node(domain, size=size, color=color, title=f"{'ROOT: ' if data['is_root'] else ''}{domain}\nTotal: {total_count}\nCompleted: {completed_count}")

    for domain, data in domain_summary.items():
        for connected_domain in data['connections']:
            if connected_domain in domain_summary:
                G.add_edge(domain, connected_domain)

    net = Network(height="1000px", width="100%", bgcolor="#222222", font_color="white")  # Increased height to 1000px

    for node in G.nodes(data=True):
        net.add_node(node[0], size=node[1]['size'], color=node[1]['color'], title=node[1]['title'])

    for edge in G.edges():
        net.add_edge(edge[0], edge[1])

    net.barnes_hut(gravity=-80000, central_gravity=0.3, spring_length=250, spring_strength=0.001, damping=0.09)
    net.set_options('''
        var options = {
          "nodes": {
            "font": {
              "size": 12
            }
          },
          "edges": {
            "color": {
              "inherit": true
            },
            "smooth": false
          },
          "physics": {
            "forceAtlas2Based": {
              "gravitationalConstant": -100,
              "centralGravity": 0.01,
              "springLength": 100,
              "springConstant": 0.08
            },
            "maxVelocity": 50,
            "minVelocity": 0.1,
            "solver": "forceAtlas2Based"
          }
        }
    ''')

    return net

# Update the summarize_network_data function to increase the number of nodes
def summarize_network_data(websites_df, max_nodes=4000):  # Increased max_nodes to 4000
    domain_summary = defaultdict(lambda: {'count': 0, 'status': defaultdict(int), 'connections': set(), 'is_root': False})

    for _, website in websites_df.iterrows():
        domain = urlparse(website['url']).netloc
        domain_summary[domain]['count'] += 1
        domain_summary[domain]['status'][website['status']] += 1

        if website['parent_url']:
            parent_domain = urlparse(website['parent_url']).netloc
            if parent_domain != domain:
                domain_summary[domain]['connections'].add(parent_domain)
                domain_summary[parent_domain]['connections'].add(domain)
        else:
            # This is a root page
            domain_summary[domain]['is_root'] = True

    # Sort domains by count and limit to max_nodes
    top_domains = sorted(domain_summary.items(), key=lambda x: x[1]['count'], reverse=True)[:max_nodes]

    return dict(top_domains)

def main():
    st.set_page_config(layout="wide")

    st.title('Web Crawler Dashboard')

    # Crawler Control Section
    st.header('Crawler Control')
    crawler_status = "Enabled" if is_crawler_enabled() else "Disabled"
    st.write(f"Crawler Status: {crawler_status}")

    col1, col2 = st.columns(2)
    with col1:
        if st.button('Start Crawler'):
            enable_crawler()
            st.success("Crawler has been started.")
            st.experimental_rerun()
    with col2:
        if st.button('Stop Crawler'):
            disable_crawler()
            st.success("Crawler has been stopped.")
            st.experimental_rerun()


    # Crawler Stats
    st.header('Crawler Stats')
    websites = get_websites()
    total_websites = len(websites)
    completed_websites = len(websites[websites['status'] == 'completed'])
    pending_websites = len(websites[websites['status'] == 'pending'])
    in_progress_websites = len(websites[websites['status'] == 'in_progress'])
    error_websites = len(websites[websites['status'] == 'error'])

    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("Total Websites", total_websites)
    col2.metric("Completed", completed_websites)
    col3.metric("Pending", pending_websites)
    col4.metric("In Progress", in_progress_websites)
    col5.metric("Error", error_websites)

    # Add new website
    st.header('Add New Website')
    new_url = st.text_input('Enter a new website URL to crawl:')
    if st.button('Add Website'):
        add_website(new_url)

    # Blacklist Management Section
    st.header('Blacklist Management')
    blacklist = get_blacklist()

    # Display current blacklist
    if not blacklist.empty:
        st.subheader('Current Blacklist')
        st.dataframe(blacklist)

        # Option to remove from blacklist
        domain_to_remove = st.selectbox('Select domain to remove from blacklist:', blacklist['domain'])
        if st.button('Remove from Blacklist'):
            remove_from_blacklist(domain_to_remove)
            st.experimental_rerun()
    else:
        st.info("The blacklist is currently empty.")

    # Add to blacklist
    st.subheader('Add to Blacklist')
    new_blacklist_domain = st.text_input('Enter domain to blacklist:')
    blacklist_reason = st.text_input('Reason for blacklisting:')
    if st.button('Add to Blacklist'):
        add_to_blacklist(new_blacklist_domain, blacklist_reason)
        st.experimental_rerun()

    # Crawl Queue Section
    st.header('Crawl Queue')
    if not websites.empty:
        # Filtering options
        st.subheader('Filter Options')
        status_filter = st.multiselect('Filter by status:', options=['pending', 'in_progress', 'completed', 'error'], default=[])
        url_search = st.text_input('Search by URL:')

        # Apply filters
        filtered_websites = websites
        if status_filter:
            filtered_websites = filtered_websites[filtered_websites['status'].isin(status_filter)]
        if url_search:
            filtered_websites = filtered_websites[filtered_websites['url'].str.contains(url_search, case=False)]

        # Display filtered queue
        st.dataframe(filtered_websites)

    else:
        st.info("No websites have been added to the crawl queue yet.")

    # Domain-based Website Section with Graph
    st.header('Domain-based Website Details and Link Graph')
    domains = websites['domain'].unique()

    if len(domains) > 0:
        selected_domain = st.selectbox('Select a domain:', domains, key='domain_selectbox')

        domain_websites = get_domain_websites(selected_domain)

        if not domain_websites.empty:
            st.subheader('Websites and Pages')
            st.dataframe(domain_websites)

            if st.button(f'Re-crawl all websites on {selected_domain}'):
                for _, website in domain_websites.iterrows():
                    rerun_website(website['id'])

            st.subheader('Website Link Graph')
            links_df = get_website_links(selected_domain)
            if not links_df.empty:
                net = create_website_graph(links_df)

                # Save the graph as an HTML file
                with tempfile.NamedTemporaryFile(delete=False, suffix='.html') as tmpfile:
                    net.save_graph(tmpfile.name)

                    # Display the graph in Streamlit
                    with open(tmpfile.name, 'r', encoding='utf-8') as f:
                        html = f.read()
                        st.components.v1.html(html, height=600)

                # Clean up the temporary file
                os.unlink(tmpfile.name)
            else:
                st.info("No links found for the selected domain.")
        else:
            st.info(f"No data available for the domain: {selected_domain}")
    else:
        st.info("No domains found.")

    # Display root websites
    total_websites = get_total_websites()
    if total_websites > 0:
        st.subheader('Root Websites')
        root_websites = get_root_websites()
        st.dataframe(root_websites)
    else:
        st.info("No websites have been crawled yet.")

    # Full Network Graph Section
    st.header('Full Crawl Network Graph')

    if st.button('Generate Full Network Graph'):
        with st.spinner('Analyzing network data...'):
            all_websites = get_all_websites()
            if not all_websites.empty:
                domain_summary = summarize_network_data(all_websites, max_nodes=4000)  # Increased to 4000 nodes

                st.success('Network data analyzed. Generating graph...')

                net = create_simplified_network_graph(domain_summary)

                # Save the graph as an HTML file
                with tempfile.NamedTemporaryFile(delete=False, suffix='.html') as tmpfile:
                    net.save_graph(tmpfile.name)

                    # Display the graph in Streamlit
                    with open(tmpfile.name, 'r', encoding='utf-8') as f:
                        html = f.read()
                        st.components.v1.html(html, height=1000)

                # Clean up the temporary file
                os.unlink(tmpfile.name)

                # Display legend
                st.subheader('Legend')
                col1, col2, col3, col4 = st.columns(4)
                col1.color_picker('Root Pages', '#FF0000', disabled=True)
                col2.color_picker('Fully Completed', '#32CD32', disabled=True)
                col3.color_picker('Mostly Completed', '#FFA500', disabled=True)
                col4.color_picker('Less than 50% Completed', '#4169E1', disabled=True)
                st.info("Node size represents the number of pages crawled in each domain. Root pages are larger and colored red. The graph shows up to 4,000 most crawled domains.")
            else:
                st.info("No websites have been crawled yet.")

    # Emails Section
    st.header('Discovered Emails')
    emails = get_emails()
    if not emails.empty:
        st.dataframe(emails)
    else:
        st.info("No emails have been discovered yet.")

if __name__ == '__main__':
    main()
