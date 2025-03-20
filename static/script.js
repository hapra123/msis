document.addEventListener('DOMContentLoaded', function() {
    // Set the date for the countdown (April 11, 2025 - Grand Finale)
    const countdownDate = new Date("April 11, 2025 09:00:00").getTime();
 
    // Update the countdown every second
    const countdownTimer = setInterval(function() {
        const now = new Date().getTime();
        const distance = countdownDate - now;
 
        const days = Math.floor(distance / (1000 * 60 * 60 * 24));
        const hours = Math.floor((distance % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
        const minutes = Math.floor((distance % (1000 * 60 * 60)) / (1000 * 60));
        const seconds = Math.floor((distance % (1000 * 60)) / 1000);
 
        document.getElementById("days").innerHTML = days.toString().padStart(2, '0');
        document.getElementById("hours").innerHTML = hours.toString().padStart(2, '0');
        document.getElementById("minutes").innerHTML = minutes.toString().padStart(2, '0');
        document.getElementById("seconds").innerHTML = seconds.toString().padStart(2, '0');
 
        if (distance < 0) {
            clearInterval(countdownTimer);
            document.getElementById("countdown").innerHTML = "<h3>The Fest Has Begun!</h3>";
        }
    }, 1000);
 
    // Events data
    const events = [
        // Sports Events (Week 1)
        {
            name: "Athletic Meet",
            date: "March 29, 2025",
            description: "Annual athletic competition featuring track and field events, relay races, and more.",
            category: "sports",
            registrationLink: "register-athletics.html",
            event_type: "running"
        },
        {
            name: "Football Tournament",
            date: "April 1-3, 2025",
            description: "Inter-college football competition with teams competing for the championship trophy.",
            category: "sports",
            registrationLink: "register-football.html",
            event_type: "football"
        },
        {
            name: "Badminton Championship",
            date: "April 2-4, 2025",
            description: "Exciting badminton matches between college teams with knockout rounds.",
            category: "sports",
            registrationLink: "register-basketball.html",
            event_type: "badminton"
        },
        {
            name: "Cricket Tournament",
            date: "March 31 - April 1, 2025",
            description: "T20 cricket matches between departments and colleges.",
            category: "sports",
            registrationLink: "register-cricket.html",
            event_type: "cricket"
        },
 
        // Cultural Events (Week 2)
        {
            name: "Dance Competition",
            date: "April 7, 2025",
            description: "Showcase your dancing skills with solo, duo, and group performances.",
            category: "cultural",
            registrationLink: "register-dance.html",
            event_type: "dancing"
        },
        {
            name: "Battle of Bands",
            date: "April 8, 2025",
            description: "Musical competition for college bands to demonstrate their talent.",
            category: "cultural",
            registrationLink: "register-bands.html",
            event_type: "singing"
        },
        {
            name: "Art Exhibition",
            date: "April 7-10, 2025",
            description: "Display of paintings, sculptures, and other art forms created by students.",
            category: "cultural",
            registrationLink: "register-art.html",
            event_type: "art"
        },
        {
            name: "Fashion Show",
            date: "April 9, 2025",
            description: "Trendy fashion showcase by student designers and models.",
            category: "cultural",
            registrationLink: "register-fashion.html",
            event_type: "fashion"
        },
 
        // Special Events
        {
            name: "Stage Program",
            date: "April 11, 2025",
            description: "Final showdown and closure of MSIS College fest Felicity. Register below to showcase your talent",
            category: "special",
            registrationLink: "https://forms.gle/nRFYkhZYVVcRxSyL6",
            event_type: "stage"
        }
    ];
 
    // Schedule data organized by weeks
    const schedule = {
        "week1": [
            {
                day: "March 29, 2025",
                events: [
                    { time: "07:00 AM", event: "Reporting Time", venue: "MIT Ground" },
                    { time: "07:30 AM", event: "Jersey Distribution", venue: "MIT Ground" },
                    { time: "08:00 AM", event: "Breakfast", venue: "MIT Ground" },
                    { time: "08:30 PM", event: "Event starts", venue: "MIT Ground" }
                ]
            },
            {
                day: "March 31, 2025",
                events: [
                    { time: "04:30 PM", event: "Cricket Tournament", venue: "MIT Ground" }
                ]
            },
            {
                day: "April 1, 2025",
                events: [
                    { time: "04:30 AM", event: "Cricket Tournament - Finals", venue: "MIT Cricket Ground" },
                ]
            },
            {
                day: "April 4, 2025",
                events: [
                    { time: "09:00 AM", event: "Basketball Championship - Finals", venue: "Sports Complex" },
                    { time: "03:00 PM", event: "Volleyball Tournament", venue: "Volleyball Court" },
                ]
            },
            {
                day: "April 5, 2025",
                events: [
                    { time: "02:00 PM", event: "Chess Tournament", venue: "Student Center" },
                ]
            },
            {
                day: "April 6, 2025",
                events: [
                    { time: "09:00 AM", event: "Badminton Tournament", venue: "Indoor Stadium" },
                    { time: "12:00 PM", event: "Table Tennis", venue: "College Grounds" }
                ]
            }
        ],
        "week2": [
            {
                day: "April 7, 2025",
                events: [
                    { time: "09:00 AM", event: "Art Exhibition - Opening", venue: "Art Gallery" },
                    { time: "11:00 AM", event: "Photography Contest Begins", venue: "Campus-wide" },
                    { time: "02:00 PM", event: "Dance Workshop", venue: "Dance Studio" },
                    { time: "06:00 PM", event: "Dance Competition", venue: "Open Air Theater" }
                ]
            },
            {
                day: "April 8, 2025",
                events: [
                    { time: "10:00 AM", event: "Debate Championship", venue: "Seminar Hall" },
                    { time: "01:00 PM", event: "Poetry Slam", venue: "Library Lawn" },
                    { time: "03:00 PM", event: "Battle of Bands - Preliminaries", venue: "Open Air Theater" },
                    { time: "07:00 PM", event: "Battle of Bands - Finals", venue: "Open Air Theater" }
                ]
            },
            {
                day: "April 9, 2025",
                events: [
                    { time: "10:00 AM", event: "Drama Competition", venue: "Main Auditorium" },
                    { time: "02:00 PM", event: "Creative Writing Contest", venue: "Library" },
                    { time: "05:00 PM", event: "Fashion Show", venue: "Open Air Theater" },
                    { time: "08:00 PM", event: "Cultural Night", venue: "College Grounds" }
                ]
            },
            {
                day: "April 10, 2025",
                events: [
                    { time: "09:00 AM", event: "Classical Music Competition", venue: "Music Room" },
                    { time: "11:00 AM", event: "Art Exhibition - Closing Day", venue: "Art Gallery" },
                    { time: "02:00 PM", event: "Film Festival", venue: "Media Center" },
                    { time: "06:00 PM", event: "Cultural Awards Night", venue: "College Grounds" }
                ]
            }
        ],
        "finale": [
            {
                day: "April 11, 2025",
                events: [
                    { time: "10:00 AM", event: "We will be right back with schedule", venue: "Library Auditorium" }
                ]
            }
        ]
    };
 
    // Display events
    function displayEvents(category = 'sports') {
        const filteredEvents = category === 'all' ? events : events.filter(event => event.category === category);
        const eventsGrid = document.getElementById('eventsGrid');
        eventsGrid.innerHTML = '';
 
        if (filteredEvents.length === 0) {
            eventsGrid.innerHTML = '<p class="no-events">No events in this category</p>';
            return;
        }
 
        filteredEvents.forEach(event => {
            const eventCard = document.createElement('div');
            eventCard.className = 'event-card';
 
            eventCard.innerHTML = `
                <div class="event-date">${event.date}</div>
                <div class="event-details">
                    <span class="event-category">${getCategoryName(event.category)}</span>
                    <h3>${event.name}</h3>
                    <p>${event.description}
                    <a href="${event.registrationLink}" class="event-link">Register</a>
                </div>
            `;
 
            eventsGrid.appendChild(eventCard);
        });
    }
 
    function getCategoryName(category) {
        switch(category) {
            case 'sports': return 'Sports';
            case 'cultural': return 'Cultural';
            case 'special': return 'Special';
            default: return 'Event';
        }
    }
 
    // Display schedule
    function displaySchedule(week = 'week1') {
        const scheduleContent = document.getElementById('scheduleContent');
        scheduleContent.innerHTML = '';
 
        if (!schedule[week] || schedule[week].length === 0) {
            scheduleContent.innerHTML = '<p class="no-schedule">No schedule available for this period</p>';
            return;
        }
 
        schedule[week].forEach(daySchedule => {
            const daySection = document.createElement('div');
            daySection.className = 'day-schedule';
 
            let dayContent = `<h3>${daySchedule.day}</h3>`;
 
            daySchedule.events.forEach(event => {
                dayContent += `
                    <div class="schedule-item">
                        <div class="schedule-time">${event.time}</div>
                        <div class="schedule-content">
                            <h4>${event.event}</h4>
                            <p class="schedule-venue">Venue: ${event.venue}</p>
                        </div>
                    </div>
                `;
            });
 
            daySection.innerHTML = dayContent;
            scheduleContent.appendChild(daySection);
        });
    }
 
    // Points Table
    function loadPointsData(eventType = 'all') {
        // Show loading indicator
        const tableBody = document.querySelector('#pointsTable tbody');
        tableBody.innerHTML = '<tr class="loading-row"><td colspan="5">Loading points data...</td></tr>';
        
        fetch('/api/points')
            .then(response => {
                if (!response.ok) {
                    throw new Error('Network response was not ok');
                }
                return response.json();
            })
            .then(data => {
                tableBody.innerHTML = '';
 
                if (data.length === 0) {
                    tableBody.innerHTML = '<tr><td colspan="5">No points data available.</td></tr>';
                    return;
                }
 
                let filteredData = data;
                if (eventType !== 'all') {
                    filteredData = data.filter(item => {
                        const event = events.find(e => e.event_type === eventType);
                        return event; // Keep items where the event exists (is not undefined)
                    });
                }
 
                filteredData.forEach(item => {
                    const row = document.createElement('tr');
                    row.innerHTML = `
                        <td>${item.rank}</td>
                        <td>${item.group}</td>
                        <td>${item.sports}</td>
                        <td>${item.cultural}</td>
                        <td>${item.total}</td>
                    `;
                    tableBody.appendChild(row);
                });
            })
            .catch(error => {
                console.error('Error fetching points data:', error);
                tableBody.innerHTML = '<tr><td colspan="5">Error loading data. Please try again.</td></tr>';
            });
    }
 
    // Function to handle the event selector change
    function handleEventSelectorChange() {
        const selectedEventType = document.getElementById('eventSelector').value;
        loadPointsData(selectedEventType);
    }
 
    // Admin Login Modal Functionality
    // Get the login modal
    var loginModal = document.getElementById("adminLoginModal");
    // Admin Panel Modal
    var adminPanel = document.getElementById("adminPanelModal");
 
    // Get the button that opens the login modal
    var btn = document.getElementById("adminLoginBtn");
 
    // Get the <span> element that closes the login modal
    var login_span = document.querySelectorAll('.close')[0];
 
    // When the user clicks the button, open the login modal
    if (btn) {
        btn.onclick = function() {
            loginModal.style.display = "block";
        }
    }
 
    // When the user clicks on <span> (x), close the login modal
    if (login_span) {
        login_span.onclick = function() {
            loginModal.style.display = "none";
        }
    }
 
    // When the user clicks anywhere outside of the login modal, close it
    window.onclick = function(event) {
        if (event.target == loginModal) {
            loginModal.style.display = "none";
        }
    }
 
    // Get the <span> element that closes the admin panel
    var admin_span = document.querySelectorAll('.close')[1];
 
    // Add Logout button
    const adminLogoutBtn = document.getElementById('adminLogoutBtn');
    if (adminLogoutBtn) {
        adminLogoutBtn.addEventListener('click', function() {
            fetch('/api/admin/logout', {
                method: 'POST'
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    adminPanel.style.display = 'none';
                    loginModal.style.display = 'block';
                    // Clear session variable
                    document.getElementById('adminUsername').value = '';
                    document.getElementById('adminPassword').value = '';
                }
            })
        });
    }
    
    // When the user clicks on <span> (x), close the admin panel
    if (admin_span) {
        admin_span.onclick = function() {
            adminPanel.style.display = "none";
            loginModal.style.display = "none";
        }
    }
    
    // Admin Login Form Submission
    const adminLoginForm = document.getElementById('adminLoginForm');
    if (adminLoginForm) {
        adminLoginForm.addEventListener('submit', function(event) {
            event.preventDefault(); // Prevent default form submission
 
            const username = document.getElementById('adminUsername').value;
            const password = document.getElementById('adminPassword').value;
            const loginError = document.getElementById('loginError');
 
            // Basic validation
            if (!username || !password) {
                loginError.textContent = 'Please enter both username and password.';
                return;
            }
 
            // Make API request to login
            fetch('/api/admin/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ username: username, password: password })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    // Login successful
                    loginError.textContent = ''; // Clear any previous errors
 
                    // Close the login modal
                    const adminLoginModal = document.getElementById('adminLoginModal');
                    adminLoginModal.style.display = 'none';
 
                    // Open the admin panel modal
                    const adminPanelModal = document.getElementById('adminPanelModal');
                    adminPanelModal.style.display = 'block';
                    loadPointsHistory();
                    // Populate the event select options after successful login
                    populateEvents();
 
                } else {
                    // Login failed
                    loginError.textContent = 'Invalid username or password.';
                }
            })
            .catch(error => {
                console.error('Login error:', error);
                loginError.textContent = 'An error occurred during login.';
            });
        });
    }
    
    // Function to populate the event select options based on the selected category
    function populateEvents() {
        const categorySelect = document.getElementById('categorySelect');
        const eventSelect = document.getElementById('eventSelect');
 
        if (!categorySelect || !eventSelect) {
            console.error('Category or Event select element not found.');
            return;
        }
 
        const selectedCategory = categorySelect.value;
 
        // Clear existing options
        eventSelect.innerHTML = '<option value="">Select Event</option>';
 
        // Filter events based on the selected category
        const filteredEvents = events.filter(event => event.category === selectedCategory);
 
        // Add new options to the event select
        filteredEvents.forEach(event => {
            const option = document.createElement('option');
            option.value = event.name;  // Use event name as the value
            option.textContent = event.name; // Use event name as the text
            eventSelect.appendChild(option);
        });
    }
    
    // Get and render the history of points.
    function loadPointsHistory() {
        const historyList = document.getElementById('pointsHistory');
        if (!historyList) return;
        
        historyList.innerHTML = '<li class="loading-item">Loading history...</li>';
        
        fetch('/api/points/history')
            .then(response => {
                if (!response.ok) {
                    throw new Error('Network response was not ok');
                }
                return response.json();
            })
            .then(data => {
                historyList.innerHTML = ''; // Clear loading item
                
                if (data.length === 0) {
                    historyList.innerHTML = '<li>No history available.</li>';
                    return;
                }
                
                data.forEach(item => {
                    const listItem = document.createElement('li');
                    listItem.textContent = `[${item.timestamp}] ${item.group} - ${item.category} - ${item.event}: +${item.points} points`;
                    historyList.appendChild(listItem);
                });
            })
            .catch(error => {
                console.error('Error fetching points history:', error);
                historyList.innerHTML = '<li class="error-item">Error loading history. Please refresh.</li>';
            });
    }
 
    const updatePointsForm = document.getElementById('updatePointsForm');
    if (updatePointsForm) {
        updatePointsForm.addEventListener('submit', function(event) {
            event.preventDefault();
 
            const groupSelect = document.getElementById('groupSelect');
            const categorySelect = document.getElementById('categorySelect');
            const eventSelect = document.getElementById('eventSelect');
            const pointsInput = document.getElementById('pointsInput');
 
            if (!groupSelect.value || !categorySelect.value || !eventSelect.value || !pointsInput.value) {
                alert('Please fill in all the fields.');
                return;
            }
            
            const data = {
                group: groupSelect.value,
                category: categorySelect.value,
                event: eventSelect.value,
                points: parseInt(pointsInput.value)
            };
            
            fetch('/api/points/update', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(data)
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    alert(data.message);
                    loadPointsData();
                    loadPointsHistory();
                } else {
                    alert('Error: ' + data.error);
                }
            })
            .catch(error => console.error('Error:', error));
        });
    }
 
    // Points Table: Event selector
    const eventSelector = document.getElementById('eventSelector');
    if (eventSelector) {
        eventSelector.addEventListener('change', handleEventSelectorChange);
    }
 
    // Refresh button
    const refreshTableBtn = document.getElementById('refreshTable');
    if (refreshTableBtn) {
        refreshTableBtn.addEventListener('click', function() {
            loadPointsData(eventSelector ? eventSelector.value : 'all');
        });
    }
    
    // Auto-refresh functionality
    const autoRefreshCheckbox = document.getElementById('autoRefresh');
    const refreshTimer = document.getElementById('refreshTimer');
    let autoRefreshInterval;
    
    function startAutoRefresh() {
        if (autoRefreshCheckbox && autoRefreshCheckbox.checked) {
            let seconds = 30;
            
            if (refreshTimer) {
                refreshTimer.textContent = seconds;
            }
            
            clearInterval(autoRefreshInterval);
            
            autoRefreshInterval = setInterval(function() {
                seconds--;
                
                if (refreshTimer) {
                    refreshTimer.textContent = seconds;
                }
                
                if (seconds <= 0) {
                    loadPointsData(eventSelector ? eventSelector.value : 'all');
                    seconds = 30;
                    if (refreshTimer) {
                        refreshTimer.textContent = seconds;
                    }
                }
            }, 1000);
        } else {
            clearInterval(autoRefreshInterval);
        }
    }
    
    if (autoRefreshCheckbox) {
        autoRefreshCheckbox.addEventListener('change', startAutoRefresh);
    }
 
    // Initial display
    function initializeApp() {
        displayEvents('sports');
        displaySchedule('week1');
        loadPointsData();
        
        // Start auto-refresh if checked
        startAutoRefresh();
    }
   
    // Event listener for the category select to populate events
    const categorySelect = document.getElementById('categorySelect');
    if (categorySelect) {
        categorySelect.addEventListener('change', populateEvents);
    }
    
    // Initialize app
    initializeApp();
 
    // Tab switching for events
    const eventTabs = document.querySelectorAll('.tab-btn');
    eventTabs.forEach(tab => {
        tab.addEventListener('click', function() {
            eventTabs.forEach(t => t.classList.remove('active'));
            this.classList.add('active');
            displayEvents(this.getAttribute('data-category'));
        });
    });
 
    // Tab switching for schedule
    const scheduleTabs = document.querySelectorAll('.schedule-tab');
    scheduleTabs.forEach(tab => {
        tab.addEventListener('click', function() {
            scheduleTabs.forEach(t => t.classList.remove('active'));
            this.classList.add('active');
            displaySchedule(this.getAttribute('data-week'));
        });
    });
 
    // Main registration button
    const mainRegisterBtn = document.getElementById('mainRegisterBtn');
    if (mainRegisterBtn) {
        mainRegisterBtn.addEventListener('click', function(e) {
            e.preventDefault();
            alert('Please select a specific event to register for from the events section.');
            document.getElementById('events').scrollIntoView({ behavior: 'smooth' });
        });
    }
 
    // Smooth scrolling for navigation
    document.querySelectorAll('nav a').forEach(anchor => {
        anchor.addEventListener('click', function(e) {
            if (this.getAttribute('href') === '#' || this.getAttribute('id') === 'adminLoginBtn') {
                return;
            }
            e.preventDefault();
            const targetId = this.getAttribute('href').substring(1);
            const target = document.getElementById(targetId);
            if (target) {
                target.scrollIntoView({ behavior: 'smooth' });
            }
        });
    });
    
    // Chatbot Functionality
    const chatbot = document.getElementById('chatbot');
    const chatbotToggle = document.getElementById('chatbotToggle');
    const chatbotClose = document.getElementById('chatbotClose');
    const chatbotSend = document.getElementById('chatbotSend');
    const chatbotInput = document.getElementById('chatbotInput');
    const chatbotBody = document.getElementById('chatbotBody');

    // Toggle chatbot visibility
    chatbotToggle.addEventListener('click', function() {
        chatbot.style.display = 'flex';
        chatbotToggle.style.display = 'none';
    });

    chatbotClose.addEventListener('click', function() {
        chatbot.style.display = 'none';
        chatbotToggle.style.display = 'block';
    });

    // Function to add message to chatbot
    function addMessage(sender, text) {
        const msgDiv = document.createElement('div');
        msgDiv.className = 'chatbot-message ' + sender;
        msgDiv.textContent = text;
        chatbotBody.appendChild(msgDiv);
        chatbotBody.scrollTop = chatbotBody.scrollHeight;
    }

    // Simple chatbot reply handling
    function getChatbotReply(message) {
        message = message.toLowerCase();
        if(message.includes('register') || message.includes('registration')) {
            return "To register, please click the 'Register' link in the event card or use the registration page.";
        }
        if(message.includes('event')) {
            return "You can view our events by scrolling to the Events section.";
        }
        return "I'm sorry, I can only help with registration queries. Please check our events for more details.";
    }

    // Send message handler
    function handleChatSend() {
        const userMessage = chatbotInput.value.trim();
        if(!userMessage) return;
        addMessage('user', userMessage);
        chatbotInput.value = '';
        setTimeout(function() {
            const reply = getChatbotReply(userMessage);
            addMessage('bot', reply);
        }, 500);
    }

    // Send button or Enter key triggers send
    chatbotSend.addEventListener('click', handleChatSend);
    chatbotInput.addEventListener('keypress', function(e) {
        if(e.key === 'Enter') {
            handleChatSend();
        }
    });
});

// Chatbot Functionality (clickable options only)
document.addEventListener('DOMContentLoaded', function() {
    const chatbot = document.getElementById('chatbot');
    const chatbotToggle = document.getElementById('chatbotToggle');
    const chatbotClose = document.getElementById('chatbotClose');
    const chatbotBody = document.getElementById('chatbotBody');

    // Toggle chatbot visibility
    chatbotToggle.addEventListener('click', function() {
        chatbot.style.display = 'flex';
        chatbotToggle.style.display = 'none';
    });

    chatbotClose.addEventListener('click', function() {
        chatbot.style.display = 'none';
        chatbotToggle.style.display = 'block';
    });

    // Function to add a message to the chatbot
    function addMessage(sender, text) {
        const msgDiv = document.createElement('div');
        msgDiv.className = 'chatbot-message ' + sender;
        msgDiv.textContent = text;
        chatbotBody.appendChild(msgDiv);
        chatbotBody.scrollTop = chatbotBody.scrollHeight;
    }

    // Event details mapping matching your events.json data
    const eventDetails = {
        "athletic meet": {
            date: "March 29, 2025",
            registrationLink: "register-athletics.html"
        },
        "football tournament": {
            date: "April 1-3, 2025",
            registrationLink: "register-football.html"
        },
        "badminton championship": {
            date: "April 2-4, 2025",
            registrationLink: "register-basketball.html"
        },
        "cricket tournament": {
            date: "March 31 - April 1, 2025",
            registrationLink: "register-cricket.html"
        }
    };

    // Utility function to capitalize each word
    function capitalize(text) {
        return text.split(' ').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ');
    }

    // Function to generate reply for a preset event option
    function getEventReply(eventKey) {
        const details = eventDetails[eventKey];
        if (details) {
            return `Registration for ${capitalize(eventKey)} is scheduled on ${details.date}. Click here to register: ${details.registrationLink}`;
        }
        return "Sorry, no details are available for this event.";
    }

    // Attach click handlers for preset event options
    document.querySelectorAll('.chatbot-option').forEach(function(button) {
        button.addEventListener('click', function() {
            const eventKey = button.getAttribute('data-event');
            addMessage('user', capitalize(eventKey));
            setTimeout(function() {
                const reply = getEventReply(eventKey);
                addMessage('bot', reply);
            }, 500);
        });
    });
});