# WebCrawl - A Simple Python Web Crawler Project

WebCrawl is a simple web crawler project that consists of three components: a Python web crawler, a Python Streamlit UI application, and a MySQL database. All components run in Docker containers, making it easy to set up and run the project.

## Components

1. **Crawler**: A Python web crawler that uses Depth-First Search (DFS) to search deeply out from a root domain.
2. **UI**: A Python Streamlit UI application that allows users to add domains to crawl and visualize the crawler's discoveries through a node map.
3. **MySQL Database**: A MySQL database that stores the data collected by the crawler.

## Getting Started

To run the WebCrawl project, follow these steps:

1. Clone the repository to your local machine:

   ```
   git clone https://github.com/yourusername/webcrawl.git
   cd webcrawl
   ```

2. Build and start the Docker containers:

   ```
   docker-compose up --build
   ```

   This command will build the Docker images and start the containers. You can access the Streamlit UI application at `http://localhost:8501`.

## Making Changes

If you make changes to the project, you can rebuild the Docker containers by following these steps:

1. Stop the running containers:

   ```
   docker-compose down
   ```

   If you've made changes to the database schema, use the `-v` flag to remove the database volume:

   ```
   docker-compose down -v
   ```

2. Rebuild and start the containers:

   ```
   docker-compose up --build
   ```

   This will rebuild the Docker images and start the containers with the latest changes.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
