import requests
from bs4 import BeautifulSoup
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, text, func, TIMESTAMP, or_
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.dialects.mysql import LONGTEXT, TEXT
from urllib.parse import urljoin, urlparse, urlunparse
import os
import time
import logging
import re
from tenacity import retry, stop_after_attempt, wait_fixed, retry_if_exception_type
from tld import get_tld

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

DATABASE_URL = os.environ.get('DATABASE_URL')

Base = declarative_base()

class Website(Base):
    __tablename__ = 'websites'
    id = Column(Integer, primary_key=True)
    url = Column(TEXT, nullable=False)
    status = Column(String(20), default='pending')
    parent_url = Column(TEXT)
    domain = Column(String(255))
    link_count = Column(Integer, default=0)
    pages = relationship('Page', back_populates='website')

class Page(Base):
    __tablename__ = 'pages'
    id = Column(Integer, primary_key=True)
    url = Column(TEXT, nullable=False)
    content = Column(LONGTEXT)
    status = Column(String(20), default='pending')
    website_id = Column(Integer, ForeignKey('websites.id'))
    website = relationship('Website', back_populates='pages')

class Email(Base):
    __tablename__ = 'emails'
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, nullable=False)
    source_url = Column(TEXT, nullable=False)

class Blacklist(Base):
    __tablename__ = 'blacklist'
    id = Column(Integer, primary_key=True)
    domain = Column(String(255), unique=True, nullable=False)
    reason = Column(String(255))
    date_added = Column(TIMESTAMP, server_default=func.now())

@retry(
    stop=stop_after_attempt(20),
    wait=wait_fixed(5),
    retry=retry_if_exception_type((Exception,)),
    before=lambda _: logger.info("Attempting to connect to the database...")
)
def get_db_session():
    try:
        engine = create_engine(DATABASE_URL)
        Base.metadata.create_all(engine)
        Session = sessionmaker(bind=engine)
        session = Session()
        # Test the connection
        session.execute(text("SELECT 1"))
        logger.info("Successfully connected to the database")
        return Session
    except Exception as e:
        logger.error(f"Error connecting to database: {str(e)}")
        raise

try:
    Session = get_db_session()
except Exception as e:
    logger.error(f"Failed to connect to the database after multiple attempts: {str(e)}")
    raise

def is_crawler_enabled():
    return os.path.exists('/app/control/crawler_enabled')

def enable_crawler():
    with open('/app/crawler_enabled', 'w') as f:
        f.write('enabled')

def disable_crawler():
    if os.path.exists('/app/crawler_enabled'):
        os.remove('/app/crawler_enabled')


def get_domain(url):
    parsed_url = urlparse(url)
    return '.'.join(parsed_url.netloc.split('.')[-2:])  # This will get 'apple.com' from 'podcasts.apple.com'

def get_domain_variations(url):
    try:
        # Add a default scheme if none is present
        if not url.startswith(('http://', 'https://')):
            url = f'http://{url}'

        parsed_url = urlparse(url)
        domain = parsed_url.netloc

        if not domain:
            return []

        # Try to get the registered domain using tld
        try:
            tld_object = get_tld(url, as_object=True)
            registered_domain = tld_object.domain + '.' + tld_object.tld
        except:
            # Fallback to simple domain extraction if tld fails
            domain_parts = domain.split('.')
            registered_domain = '.'.join(domain_parts[-2:]) if len(domain_parts) > 1 else domain

        variations = [
            domain,  # Full domain
            registered_domain,  # Registered domain
            f'%.{registered_domain}',  # Wildcard for subdomains
        ]
        return list(set([v for v in variations if v]))  # Remove duplicates and empty strings
    except Exception as e:
        logger.error(f"Error getting domain variations for {url}: {str(e)}")
        # Attempt to return at least the input as a variation if all else fails
        return [url.replace('http://', '').replace('https://', '').split('/')[0]]

def add_to_blacklist(session, url, reason="Exceeded link limit"):
    domain_variations = get_domain_variations(url)
    if not domain_variations:
        logger.warning(f"No valid domain variations found for {url}. Skipping blacklist addition.")
        return

    for domain in domain_variations:
        try:
            blacklist_entry = Blacklist(domain=domain, reason=reason)
            session.add(blacklist_entry)
            session.flush()  # Try to flush each entry individually
        except IntegrityError:
            session.rollback()  # Rollback the individual entry if it's a duplicate
            logger.warning(f"Domain {domain} already in blacklist. Skipping.")
        except Exception as e:
            session.rollback()
            logger.error(f"Error adding {domain} to blacklist: {str(e)}")

    try:
        # Update all pending websites for these domain variations to 'blacklisted'
        for domain in domain_variations:
            websites_to_update = session.query(Website).filter(
                Website.domain.like(f'%{domain}'),
                Website.status.in_(['pending', 'in_progress'])
            ).all()

            for website in websites_to_update:
                website.status = 'blacklisted'

        session.commit()
        logger.info(f"Domain {domain_variations[0]} and its variations added to blacklist. Websites updated to 'blacklisted'.")
    except Exception as e:
        session.rollback()
        logger.error(f"Error updating websites for blacklisted domains: {str(e)}")

def check_and_blacklist_domain(session, url):
    domain_variations = get_domain_variations(url)
    if not domain_variations:
        logger.warning(f"No valid domain variations found for {url}. Skipping blacklist check.")
        return False

    try:
        domain_count = session.query(func.count(Website.id)).filter(
            or_(*[Website.domain.like(f'%{domain}') for domain in domain_variations])
        ).scalar()
        if domain_count > 25:
            add_to_blacklist(session, url)
            return True
        else:
            logger.info(f"Domain count for {url}: {domain_count}")
    except Exception as e:
        logger.error(f"Error checking domain count for {url}: {str(e)}")
    return False

def is_blacklisted(session, url):
    domain_variations = get_domain_variations(url)
    if not domain_variations:
        logger.warning(f"No valid domain variations found for {url}. Assuming not blacklisted.")
        return False

    try:
        blacklisted = session.query(Blacklist).filter(
            or_(*[Blacklist.domain.like(domain) for domain in domain_variations])
        ).first()
        return blacklisted is not None
    except Exception as e:
        logger.error(f"Error checking blacklist for {url}: {str(e)}")
        return False

def extract_emails(text, url):
    # Updated regex to be more specific
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'
    emails = re.findall(email_pattern, text)

    # Additional filtering
    valid_emails = []
    for email in set(emails):
        # Check if the email contains invalid sequences
        if '@2x.' not in email and not email.endswith('.png') and not email.endswith('.jpg'):
            # Split the email into local part and domain
            local, domain = email.split('@')

            # Additional checks on the domain
            if '.' in domain and not domain.startswith('.') and not domain.endswith('.'):
                valid_emails.append((email, url))

    return valid_emails

def add_emails(session, emails):
    for email, source_url in emails:
        try:
            existing_email = session.query(Email).filter_by(email=email).first()
            if not existing_email:
                new_email = Email(email=email, source_url=source_url)
                session.add(new_email)
                session.commit()
        except IntegrityError:
            session.rollback()
            logger.warning(f"Email {email} already exists in the database.")
        except Exception as e:
            session.rollback()
            logger.error(f"Error adding email {email}: {str(e)}")


def is_valid_url(url):
    parsed = urlparse(url)
    return bool(parsed.netloc) and bool(parsed.scheme) and parsed.scheme in ('http', 'https')

def clean_url(url):
    parsed = urlparse(url)
    # Remove unnecessary query parameters
    clean_query = '&'.join([p for p in parsed.query.split('&') if not p.startswith('utm_')])
    # Reconstruct the URL without unnecessary parts
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, clean_query, ''))

def crawl_page(session, page):
    try:
        logger.info(f"Crawling {page.url}")

        if is_blacklisted(session, page.url):
            logger.info(f"URL {page.url} belongs to a blacklisted domain. Skipping.")
            page.status = 'blacklisted'
            session.commit()
            return []

        response = requests.get(page.url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')

        page.content = response.text
        page.status = 'completed'
        session.commit()

        website = page.website
        if not website:
            logger.error(f"Website not found for page: {page.url}")
            return []

        domain = get_domain(page.url)
        website.domain = domain

        if check_and_blacklist_domain(session, domain):
            logger.info(f"Domain {domain} blacklisted due to exceeding link limit. Stopping crawl.")
            return []

        # Extract and add emails
        emails = extract_emails(response.text, page.url)
        add_emails(session, emails)

        child_links = []
        for link in soup.find_all('a', href=True):
            href = link['href']
            full_url = urljoin(page.url, href)
            clean_full_url = clean_url(full_url)
            if is_valid_url(clean_full_url) and not is_blacklisted(session, clean_full_url):
                child_website = add_or_update_website(session, clean_full_url, page.url)
                child_links.append(child_website)

        session.commit()
        return child_links
    except Exception as e:
        logger.error(f"Error crawling {page.url}: {str(e)}")
        page.status = 'error'
        session.commit()
        return []

def add_or_update_website(session, url, parent_url=None):
    website = session.query(Website).filter_by(url=url).first()
    if not website:
        domain = get_domain(url)
        website = Website(url=url, status='pending', parent_url=parent_url, domain=domain)
        session.add(website)
        logger.info(f"Added new website to crawl: {url}")
    return website

def crawl_website(website_id):
    session = Session()
    try:
        website = session.query(Website).get(website_id)
        if not website:
            logger.error(f"Website with id {website_id} not found in database")
            return

        if is_blacklisted(session, website.url):
            logger.info(f"Website {website.url} is blacklisted. Skipping.")
            website.status = 'blacklisted'
            session.commit()
            return

        logger.info(f"Starting to crawl {website.url}")
        website.status = 'in_progress'
        session.commit()

        # Ensure the main page is in the database
        main_page = session.query(Page).filter_by(url=website.url, website_id=website.id).first()
        if not main_page:
            main_page = Page(url=website.url, website=website, status='pending')
            session.add(main_page)
            session.commit()

        crawl_page(session, main_page)

        website.status = 'completed'
        session.commit()
        logger.info(f"Finished crawling {website.url}")
    except Exception as e:
        logger.error(f"Error during crawl of website {website.url}: {str(e)}")
        website.status = 'error'
        session.commit()
    finally:
        session.close()

MAX_DEPTH = 25  # You can adjust this value

def crawl_website_dfs(website_id, max_depth=MAX_DEPTH):
    session = Session()
    try:
        website = session.query(Website).get(website_id)
        if not website:
            logger.error(f"Website with id {website_id} not found in database")
            return

        logger.info(f"Starting to crawl {website.url}")
        website.status = 'in_progress'
        session.commit()

        stack = [(website, 0)]  # (website, depth)
        while stack:
            current_website, depth = stack.pop()
            if current_website.status != 'completed' and not is_blacklisted(session, current_website.url) and depth < max_depth:
                main_page = session.query(Page).filter_by(url=current_website.url, website_id=current_website.id).first()
                if not main_page:
                    main_page = Page(url=current_website.url, website=current_website, status='pending')
                    session.add(main_page)
                    session.commit()

                child_websites = crawl_page(session, main_page)
                for child in child_websites:
                    if child.status == 'pending':
                        stack.append((child, depth + 1))

            current_website.status = 'completed'
            session.commit()

        website.status = 'completed'
        session.commit()
        logger.info(f"Finished crawling {website.url} and its child links")
    except Exception as e:
        logger.error(f"Error during crawl of website {website.url}: {str(e)}")
        website.status = 'error'
        session.commit()
    finally:
        session.close()

    time.sleep(1)  # Add a small delay between website crawls

if __name__ == "__main__":
    logger.info("Crawler service started")
    while True:
        try:
            if is_crawler_enabled():
                session = Session()
                try:
                    pending_website = session.query(Website).filter(
                        Website.status == 'pending'
                    ).order_by(Website.id).first()

                    if pending_website:
                        if not is_blacklisted(session, pending_website.url):
                            logger.info(f"Starting to crawl: {pending_website.url}")
                            crawl_website_dfs(pending_website.id)
                        else:
                            logger.info(f"Website {pending_website.url} belongs to blacklisted domain. Updating status.")
                            pending_website.status = 'blacklisted'
                            session.commit()
                    else:
                        logger.info("No pending websites found")
                except Exception as e:
                    logger.error(f"Error in crawler loop: {str(e)}")
                    session.rollback()
                finally:
                    session.close()
            else:
                logger.info("Crawler is disabled. Waiting for enable signal.")
        except Exception as e:
            logger.error(f"Error in main crawler loop: {str(e)}")

        time.sleep(2)
